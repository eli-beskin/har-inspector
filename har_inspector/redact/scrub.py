"""Redact secrets in a raw HAR dict: first by name, then every echo of their values.

Pass 1 replaces values found by name (headers, cookies, query/form/multipart/JSON
parameters, WebSocket frames) or by position (URL userinfo passwords) and
remembers them. Pass 2 replaces those values in every string of
the document, because servers and browsers echo them (bodies, Referer, Location,
page titles, initiator stacks). Entries and names are never removed.
"""

import base64
import copy
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import quote, quote_plus, unquote, unquote_plus

from har_inspector import __version__
from har_inspector.redact.names import URL_HEADERS, is_secret_header, is_secret_param
from har_inspector.urls import REDACTED, USERINFO, map_pairs, map_url

# The userinfo marker is the URL-encoded REDACTED: urlsplit() rejects "[" in the
# authority (ValueError on Python 3.11+), and the detectors urlsplit every URL,
# so "user:[REDACTED]@host" would crash analyzing the redacted file.
USERINFO_MARKER = quote(REDACTED, safe="")
# Shorter values are redacted only where found by name: replacing e.g. "pass"
# everywhere would corrupt unrelated text.
MIN_GLOBAL_LENGTH = 8

_URL_START = re.compile(r"[a-z][a-z0-9+.-]*://", re.IGNORECASE)
# k=v&k=v with no spaces: urlencoded data sent as text/plain or without a type.
_PAIRS = re.compile(r"[^=&\s]+=[^&\s]*(?:&[^=&\s]+=[^&\s]*)*")
_BOUNDARY = re.compile(r'boundary=(?:"([^"]+)"|([^;\s]+))', re.IGNORECASE)
# One multipart part after its delimiter: line end, headers, blank line, body, and
# the line end that belongs to the next delimiter.
_PART = re.compile(r"(\r?\n)(.*?)(\r?\n\r?\n)(.*?)(\r?\n)?", re.DOTALL)
# "; name=" so that "filename=" doesn't match.
_PART_NAME = re.compile(
    r'^content-disposition:[^\r\n]*?;\s*name=(?:"([^"]*)"|([^;\s]+))',
    re.IGNORECASE | re.MULTILINE,
)
_PART_TYPE = re.compile(r"^content-type:[ \t]*([^\r\n]*)", re.IGNORECASE | re.MULTILINE)


@dataclass(frozen=True)
class NotScanned:
    entry: int
    mime_type: str
    reason: str


@dataclass
class Stats:
    entries: int = 0
    # Counters are keyed by header / parameter name, never by value.
    headers: Counter = field(default_factory=Counter)
    cookies: int = 0  # request/response cookies[] values
    query: Counter = field(default_factory=Counter)  # request.queryString
    url_params: Counter = field(default_factory=Counter)  # inside URL strings
    post_params: Counter = field(default_factory=Counter)  # postData.params
    post_text: Counter = field(default_factory=Counter)  # postData.text
    response_bodies: Counter = field(default_factory=Counter)
    websocket: Counter = field(default_factory=Counter)  # _webSocketMessages data
    userinfo: Counter = field(default_factory=Counter)  # URL passwords, by location
    scrub: Counter = field(default_factory=Counter)  # location category -> replacements
    secrets: int = 0  # distinct secret values found by name
    global_secrets: int = 0  # of those, long enough to be scrubbed everywhere
    not_scanned: list[NotScanned] = field(default_factory=list)


def redact(har: dict, now: datetime) -> tuple[dict, Stats]:
    """Return a redacted copy of `har` (left untouched) and what was done.

    `now` must be UTC; it dates the note added to log.comment.
    """
    doc = copy.deepcopy(har)
    log = doc["log"]
    r = _Redactor()
    for index, entry in enumerate(log["entries"]):
        if isinstance(entry, dict):
            r.entry(index, entry)
    for page in _dicts(log.get("pages")):
        # Chrome titles a page without <title> by its URL.
        if isinstance(page.get("title"), str) and _URL_START.match(page["title"]):
            page["title"] = r._url(page["title"])
    r.userinfo(doc)
    r.scrub(doc)
    r.reencode()
    # Added after the scrub so the note itself is never scrubbed; an existing
    # comment was scrubbed like any other string and is kept.
    note = f"Redacted by har-inspector {__version__} on {now:%Y-%m-%d} UTC"
    old = log.get("comment")
    log["comment"] = f"{old}\n{note}" if old else note
    r.stats.entries = len(log["entries"])
    return doc, r.stats


class _Redactor:
    def __init__(self):
        self.stats = Stats()
        self.secrets: set[str] = set()
        # Base64 bodies decoded for scanning: (content dict, original base64,
        # decoded text), re-encoded by reencode() once both passes are done.
        self.decoded: list[tuple[dict, str, str]] = []
        self.index = 0  # entry being redacted, for NOT SCANNED rows

    # -- pass 1: by name ------------------------------------------------------

    def entry(self, index: int, entry: dict) -> None:
        self.index = index
        request = _dict(entry.get("request"))
        response = _dict(entry.get("response"))
        for message in (request, response):
            for h in _dicts(message.get("headers")):
                self._header(h)
            for c in _dicts(message.get("cookies")):
                if self._keep(c.get("value")):
                    c["value"] = REDACTED
                    self.stats.cookies += 1
        for q in _dicts(request.get("queryString")):
            name = str(q.get("name", ""))
            if is_secret_param(name) and self._keep_param(q.get("value")):
                q["value"] = REDACTED
                self.stats.query[name] += 1
        for message, key in ((request, "url"), (response, "redirectURL")):
            if isinstance(message.get(key), str):
                message[key] = self._url(message[key])
        self._initiator(entry.get("_initiator"))
        post = _dict(request.get("postData"))
        # Multipart params too: Firefox lists each part here (with fileName).
        for p in _dicts(post.get("params")):
            name = str(p.get("name", ""))
            if is_secret_param(name) and self._keep_param(p.get("value")):
                p["value"] = REDACTED
                self.stats.post_params[name] += 1
        if isinstance(post.get("text"), str):
            post["text"] = self._body(post.get("mimeType"), post["text"],
                                      self.stats.post_text)
        content = _dict(response.get("content"))
        if isinstance(content.get("text"), str) and content["text"]:
            self._content(index, content)
        for m in _dicts(entry.get("_webSocketMessages")):
            if not isinstance(m.get("data"), str):
                continue
            if m.get("opcode", 1) == 1:
                m["data"] = self._frame(m["data"])
            elif m["data"]:
                self._not_scanned(index, "websocket", "binary WebSocket frame")

    def _keep(self, value) -> bool:
        """Remember a secret value; False if there is nothing to redact."""
        if value is None or isinstance(value, bool):
            return False
        value = str(value).strip()
        if not value or value in (REDACTED, USERINFO_MARKER):
            return False
        self.secrets.add(value)
        if len(value) > 2 and value[0] == value[-1] == '"':
            self.secrets.add(value[1:-1])  # quoted cookie value
        return True

    def _keep_param(self, value) -> bool:
        # The same value appears encoded in URLs and decoded elsewhere.
        if not self._keep(value):
            return False
        self._keep(unquote_plus(str(value)))
        return True

    def _header(self, h: dict) -> None:
        value = h.get("value")
        if not isinstance(value, str):
            return
        name = str(h.get("name", "")).lower()
        if name == "cookie":
            new = ";".join(self._cookie_pair(part) for part in value.split(";"))
        elif name == "set-cookie":
            # Firefox joins several Set-Cookie headers with newlines. Only the
            # leading name=value is secret; attributes (SameSite...) are kept.
            new = "\n".join(self._set_cookie(line) for line in value.split("\n"))
        elif name in ("authorization", "proxy-authorization"):
            new = self._authorization(value)
        elif is_secret_header(name):
            new = REDACTED if self._keep(value) else value
        elif name in URL_HEADERS:
            h["value"] = self._url(value)  # counted per parameter in url_params
            return
        else:
            return
        if new != value:
            h["value"] = new
            self.stats.headers[name] += 1

    def _cookie_pair(self, part: str) -> str:
        name, eq, value = part.partition("=")
        if not eq:
            # A bare value without a name: keep its leading space, hide the rest.
            lead = part[: len(part) - len(part.lstrip())]
            return lead + REDACTED if self._keep(part) else part
        return f"{name}={REDACTED}" if self._keep(value) else part

    def _set_cookie(self, line: str) -> str:
        pair, sep, attributes = line.partition(";")
        return self._cookie_pair(pair) + sep + attributes

    def _authorization(self, value: str) -> str:
        parts = value.strip().split(None, 1)
        if len(parts) < 2:
            return REDACTED if self._keep(value) else value
        scheme, credentials = parts
        if not self._keep(credentials):
            return value
        if scheme.lower() == "basic":
            # The password may be echoed elsewhere in clear text.
            try:
                decoded = base64.b64decode(credentials, validate=True).decode("utf-8")
            except ValueError:
                decoded = ""
            self._keep(decoded.partition(":")[2])
        return f"{scheme} {REDACTED}"

    def _url(self, url: str) -> str:
        # Query and fragment only: userinfo passwords are handled in every
        # string at once by userinfo().
        return map_url(url, lambda _: None, self._param(self.stats.url_params))

    def _param(self, counter: Counter):
        def replace(name: str, value: str) -> str | None:
            if is_secret_param(name) and self._keep_param(value):
                counter[name] += 1
                return REDACTED
            return None
        return replace

    def _initiator(self, node) -> None:
        # Chrome's _initiator: url, and stack.callFrames[].url with parent stacks.
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "url" and isinstance(value, str):
                    node[key] = self._url(value)
                else:
                    self._initiator(value)
        elif isinstance(node, list):
            for value in node:
                self._initiator(value)

    def _body(self, mime_type, text: str, counter: Counter) -> str:
        raw_type = str(mime_type or "")  # the multipart boundary is case-sensitive
        mime_type = raw_type.lower()
        if "multipart/form-data" in mime_type:
            return self._multipart(raw_type, text, counter)
        if "x-www-form-urlencoded" in mime_type:
            return map_pairs(text, self._param(counter))
        if "json" in mime_type or text.lstrip()[:1] in ("{", "["):
            try:
                doc = json.loads(text)
            except ValueError:
                return text  # left to the value scrub
            if self._json(doc, None, counter):
                return json.dumps(doc, ensure_ascii=False, separators=(",", ":"))
            return text
        # sendBeacon and analytics libraries post k=v&k=v as text/plain or untyped.
        if mime_type.split(";")[0].strip() in ("", "text/plain") and _PAIRS.fullmatch(text):
            return map_pairs(text, self._param(counter))
        return text

    def _multipart(self, mime_type: str, text: str, counter: Counter) -> str:
        m = _BOUNDARY.search(mime_type)
        boundary = (m[1] or m[2]) if m else ""
        if not boundary and text.startswith("--"):
            # No boundary parameter: the first line is the delimiter.
            boundary = text.splitlines()[0][2:].strip()
        delimiter = f"--{boundary}"
        if not boundary or delimiter not in text:
            self._not_scanned(self.index, mime_type, "multipart body without boundary")
            return text
        # chunks[0] is the preamble; the closing delimiter leaves a chunk starting "--".
        chunks = text.split(delimiter)
        return delimiter.join(chunks[:1] + [self._part(c, counter) for c in chunks[1:]])

    def _part(self, chunk: str, counter: Counter) -> str:
        m = None if chunk.startswith("--") else _PART.fullmatch(chunk)
        if not m:
            return chunk  # closing delimiter, or no blank line after the headers
        lead, headers, blank, body, tail = m.groups()
        name = _PART_NAME.search(headers)
        name = (name[1] if name[1] is not None else name[2]) if name else ""
        if is_secret_param(name):
            if self._keep(body):
                body = REDACTED
                counter[name] += 1
        else:
            # A JSON or form part (or an uploaded JSON file) is redacted by key.
            part_type = _PART_TYPE.search(headers)
            body = self._body(part_type[1] if part_type else None, body, counter)
        return lead + headers + blank + body + (tail or "")

    def _frame(self, data: str) -> str:
        # Socket.IO / Engine.IO put the packet type before the JSON: 42["auth",{...}]
        prefix = re.match(r"\d*", data)[0]
        rest = data[len(prefix):]
        if prefix and rest[:1] in ("[", "{"):
            return prefix + self._body(None, rest, self.stats.websocket)
        return self._body(None, data, self.stats.websocket)

    def _json(self, node, owner: str | None, counter: Counter) -> bool:
        """Redact scalars under secret keys; everything below a secret key counts
        as secret ({"session": {"id": ...}}). Returns whether anything changed."""
        if isinstance(node, dict):
            items = [(k, k if is_secret_param(str(k)) else owner, v)
                     for k, v in node.items()]
        elif isinstance(node, list):
            items = [(i, owner, v) for i, v in enumerate(node)]
        else:
            return False
        changed = False
        for key, key_owner, value in items:
            if isinstance(value, (dict, list)):
                changed |= self._json(value, key_owner, counter)
            elif key_owner is not None and self._keep(value):
                node[key] = REDACTED
                counter[key_owner] += 1
                changed = True
        return changed

    def _content(self, index: int, content: dict) -> None:
        mime_type = str(content.get("mimeType") or "")
        text = content["text"]
        if content.get("encoding") == "base64":
            if not _text_like(mime_type):
                self._not_scanned(index, mime_type, "binary base64 body")
                return
            try:
                text = base64.b64decode(text).decode("utf-8")
            except ValueError:  # binascii.Error and UnicodeDecodeError
                self._not_scanned(index, mime_type, "base64 body is not UTF-8 text")
                return
            self.decoded.append((content, content["text"], text))
        content["text"] = self._body(mime_type, text, self.stats.response_bodies)

    def _not_scanned(self, index: int, mime_type: str, reason: str) -> None:
        self.stats.not_scanned.append(NotScanned(index, mime_type or "?", reason))

    def userinfo(self, doc: dict) -> None:
        """URL passwords (scheme://user:password@host) in every string: request.url,
        headers, initiator stacks, page titles and bodies alike. They are found by
        position, so short ones are redacted too wherever they appear in a URL."""
        self._userinfo_walk(doc, ())

    def _userinfo_walk(self, node, path: tuple) -> None:
        items = node.items() if isinstance(node, dict) else enumerate(node)
        for key, value in list(items):
            if isinstance(value, str):
                if "://" in value:
                    where = path + (key,)
                    new = USERINFO.sub(lambda m: self._password(m, where), value)
                    if new != value:
                        node[key] = new
            elif isinstance(value, (dict, list)):
                self._userinfo_walk(value, path + (key,))

    def _password(self, m: re.Match, path: tuple) -> str:
        password = m[3]
        if not self._keep(password):
            return m[0]  # already redacted
        self._keep(unquote(password))  # "+" is literal in userinfo: not unquote_plus
        self.stats.userinfo[_category(path)] += 1
        return f"{m[1]}{m[2]}:{USERINFO_MARKER}@"

    # -- pass 2: by value -----------------------------------------------------

    def scrub(self, doc: dict) -> None:
        self.stats.secrets = len(self.secrets)
        long_values = [s for s in self.secrets if len(s) >= MIN_GLOBAL_LENGTH]
        self.stats.global_secrets = len(long_values)
        forms = {
            form
            for s in long_values
            for form in (s, quote(s, safe=""), quote_plus(s), unquote_plus(s))
            # A form inside "[REDACTED]" would re-redact our own marker.
            if len(form) >= MIN_GLOBAL_LENGTH
            and form not in REDACTED and form not in USERINFO_MARKER
        }
        if not forms:
            return
        # Longest first: alternation takes the first match, so a secret that
        # contains another one is replaced whole.
        pattern = re.compile("|".join(
            re.escape(f) for f in sorted(forms, key=lambda f: (-len(f), f))
        ))
        self._walk(doc, pattern, ())

    def _walk(self, node, pattern: re.Pattern, path: tuple) -> None:
        items = node.items() if isinstance(node, dict) else enumerate(node)
        for key, value in list(items):
            if isinstance(value, str):
                new, n = pattern.subn(REDACTED, value)
                if n:
                    node[key] = new
                    self.stats.scrub[_category(path + (key,))] += n
            elif isinstance(value, (dict, list)):
                self._walk(value, pattern, path + (key,))

    def reencode(self) -> None:
        for content, original, decoded in self.decoded:
            if content["text"] == decoded:
                content["text"] = original  # unchanged: keep it byte for byte
            else:
                content["text"] = base64.b64encode(content["text"].encode("utf-8")).decode()


def _category(path: tuple) -> str:
    keys = [p for p in path if isinstance(p, str)]
    last = keys[-1] if keys else ""
    if "pages" in keys and last == "title":
        return "page title"
    if "_initiator" in keys:
        return "initiator"
    if "_webSocketMessages" in keys:
        return "websocket"
    if last == "text" and ("content" in keys or "postData" in keys):
        return "body"
    if "headers" in keys:
        return "header"
    if "cookies" in keys:
        return "cookie"
    if last in ("url", "redirectURL") or "queryString" in keys:
        return "url"
    return "other"


def _text_like(mime_type: str) -> bool:
    base = mime_type.split(";")[0].strip().lower()
    return base.startswith("text/") or any(
        kind in base for kind in ("json", "xml", "javascript", "x-www-form-urlencoded")
    )


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _dicts(value) -> list[dict]:
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []
