"""URL helpers shared by redaction and the report renderers.

Both must agree on what a URL secret is, so the userinfo pattern and the
query/fragment walk live here once.
"""

import re
from urllib.parse import unquote_plus

from har_inspector.redact.names import is_secret_param

REDACTED = "[REDACTED]"

# scheme://user:password@host. The authority ends at "/", "?", "#" or whitespace;
# quotes, angle brackets and backslashes end it too, so a URL inside JSON or HTML
# can't swallow the text after it. The password runs to the last "@" of the
# authority (browsers encode "@" in a password, hand-written URLs may not).
# No ":" or an empty password ("mailto://a@b", "https://u:@h"): nothing to hide.
USERINFO = re.compile(
    r"\b([a-z][a-z0-9+.-]*://)([^/?#\s@:\"'<>\\]*):([^/?#\s\"'<>\\]+)@", re.IGNORECASE
)
# In report text URLs are delimited by whitespace; a quote inside a query must not
# end the match before a secret param.
_URL_IN_TEXT = re.compile(r"\b[a-z][a-z0-9+.-]*://\S+", re.IGNORECASE)


def map_url(url: str, password, param) -> str:
    """Rewrite the userinfo password and the query/fragment parameters of `url`.

    password(raw) and param(name, raw_value) return the new raw text, or None to
    keep it. Everything else stays byte-identical.
    """
    m = USERINFO.match(url)
    if m:
        new = password(m[3])
        if new is not None:
            url = f"{m[1]}{m[2]}:{new}@{url[m.end():]}"
    # The fragment too: the OAuth implicit flow returns #access_token=...
    base, hash_, fragment = url.partition("#")
    path, q, query = base.partition("?")
    if q:
        query = map_pairs(query, param)
    if hash_ and "=" in fragment:
        fragment = map_pairs(fragment, param)
    return path + q + query + hash_ + fragment


def map_pairs(text: str, param) -> str:
    # Split by hand rather than parse_qsl/urlencode so that parameters we
    # don't touch stay byte-identical (encoding, order, empty values).
    out = []
    for pair in text.split("&"):
        raw_name, eq, value = pair.partition("=")
        if eq:
            new = param(unquote_plus(raw_name), value)
            if new is not None:
                pair = f"{raw_name}={new}"
        out.append(pair)
    return "&".join(out)


def mask_url(url: str) -> str:
    """`url` for display: userinfo password and secret-named params hidden."""
    return map_url(url, lambda _: REDACTED, _mask_param)


def mask_urls_in_text(text: str) -> str:
    """Free text (finding titles, "METHOD url" endpoints) with every URL masked."""
    return _URL_IN_TEXT.sub(lambda m: mask_url(m[0]), text)


def _mask_param(name: str, value: str) -> str | None:
    # Same rule as redaction: an empty value has nothing to hide.
    return REDACTED if value and is_secret_param(name) else None
