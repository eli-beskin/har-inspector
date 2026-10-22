import pytest

from har_inspector.redact.names import is_secret_header, is_secret_param


@pytest.mark.parametrize("name", [
    "Cookie", "set-cookie", "Authorization", "PROXY-AUTHORIZATION", "x-api-key",
    "X-Auth-Token", "x-csrf-token", "X-XSRF-TOKEN", "x-session-id", "x-hub-signature",
    "x-client-secret", "X-Amz-Security-Token", "x-goog-api-key",
])
def test_secret_headers(name):
    assert is_secret_header(name)


@pytest.mark.parametrize("name", [
    "www-authenticate", "x-goog-authuser", "x-client-data", "accept", "keep-alive",
    ":path", "referer", "access-control-allow-headers", "content-type",
])
def test_non_secret_headers(name):
    assert not is_secret_header(name)


@pytest.mark.parametrize("name", [
    "token", "access_token", "ID_TOKEN", "refresh_token", "api_key", "apiKey", "key",
    "code", "session", "sid", "sig", "signature", "password", "pwd", "secret",
    "client_secret", "auth", "f.sid", "sessionId", "csrf_token", "accessToken",
    "X-Amz-Signature", "private_key",
])
def test_secret_params(name):
    assert is_secret_param(name)


@pytest.mark.parametrize("name", [
    "page", "country_code", "keyboard", "authuser", "hasfast", "state", "_reqid",
    "keyword", "monkey", "hl", "expires_in", "user",
])
def test_non_secret_params(name):
    assert not is_secret_param(name)
