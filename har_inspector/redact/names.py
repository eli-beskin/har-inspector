"""Which header / parameter names carry secrets. All checks are case-insensitive.

Over-matching only hides a value; under-matching leaks one. The tables are
pinned by tests/test_redact_names.py.
"""

import re

_SECRET_HEADERS = {
    "cookie", "set-cookie", "authorization", "proxy-authorization",
    "x-api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token", "x-access-token",
    "x-refresh-token", "x-session-id", "x-amz-security-token",
}
# A header is also secret if any of its "-"/"_" parts is one of these words.
_SECRET_HEADER_WORDS = {
    "token", "secret", "password", "apikey", "csrf", "xsrf", "signature", "session",
}

_SECRET_PARAMS = {
    "token", "access_token", "id_token", "refresh_token", "api_key", "apikey", "key",
    "code", "session", "sid", "sig", "signature", "password", "passwd", "pwd",
    "secret", "client_secret", "auth",
}
# A parameter is also secret if any of its words is one of these ("f.sid",
# "sessionId", "csrf_token"). "key", "code" and "auth" only count as whole names
# (or "<api|secret|private|access>_key"): as parts they hit "keyboard",
# "country_code", "authuser".
_SECRET_PARAM_WORDS = {
    "token", "secret", "password", "passwd", "signature", "sid", "session", "apikey",
    "csrf", "xsrf",
}
_KEY_QUALIFIERS = {"api", "secret", "private", "access"}

# HTTP/2 pseudo-headers and headers whose value is a URL: their query string
# and fragment get the same by-name parameter redaction as request.url.
URL_HEADERS = {":path", "referer", "location", "content-location"}


def is_secret_header(name: str) -> bool:
    name = name.lower()
    if name in _SECRET_HEADERS:
        return True
    parts = re.split(r"[-_]", name)
    return bool(_SECRET_HEADER_WORDS.intersection(parts)) or (
        len(parts) > 1 and parts[-1] == "key"
    )


def is_secret_param(name: str) -> bool:
    if name.lower() in _SECRET_PARAMS:
        return True
    words = _words(name)
    if _SECRET_PARAM_WORDS.intersection(words):
        return True
    return len(words) > 1 and words[-1] == "key" and words[-2] in _KEY_QUALIFIERS


def _words(name: str) -> list[str]:
    # "accessToken" -> access, token; "f.sid" -> f, sid; "API-Key" -> api, key
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return [w for w in re.split(r"[\s_.\-]+", spaced.lower()) if w]
