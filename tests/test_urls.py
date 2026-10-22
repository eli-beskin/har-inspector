import pytest

from har_inspector.render_common import endpoint, url
from har_inspector.urls import mask_url, mask_urls_in_text

R = "[REDACTED]"


@pytest.mark.parametrize("raw, masked", [
    ("https://user:pass@h.example/p", f"https://user:{R}@h.example/p"),
    # An unencoded "@" in the password: up to the last "@" of the authority.
    ("https://u:p@ss@h.example/p", f"https://u:{R}@h.example/p"),
    ("https://:pw@h.example/", f"https://:{R}@h.example/"),
    # Nothing to hide: no password, empty password, "@" after the authority.
    ("https://user@h.example/", "https://user@h.example/"),
    ("https://u:@h.example/", "https://u:@h.example/"),
    ("https://h.example/a@b?x=c@d", "https://h.example/a@b?x=c@d"),
    ("https://h.example:8443/p", "https://h.example:8443/p"),
    # Query and fragment: secret names only, others byte-identical.
    ("https://h.example/?a=%20&token=t&authuser=0#access_token=x&state=s",
     f"https://h.example/?a=%20&token={R}&authuser=0#access_token={R}&state=s"),
    ("https://h.example/?token=&code", "https://h.example/?token=&code"),
    ("https://h.example/#section-2", "https://h.example/#section-2"),
])
def test_mask_url(raw, masked):
    assert mask_url(raw) == masked


def test_mask_urls_in_text():
    text = "Redirect loop: https://u:pw@h.example/a?sid=1&q='x' (starts at GET https://u:pw@h.example/a)"
    # A quote inside the query does not end the URL before the next param.
    assert mask_urls_in_text(text) == (
        f"Redirect loop: https://u:{R}@h.example/a?sid={R}&q='x' "
        f"(starts at GET https://u:{R}@h.example/a)"
    )
    assert mask_urls_in_text("no url here: a=b token=c") == "no url here: a=b token=c"


def test_masked_before_truncation():
    # 10 + 100 + 14 = 124 chars: cut first, the "@" would be gone and the "p"s
    # left in place. Masked first, it is 10 + 10 + 14 = 34 chars, no cut.
    assert url("https://u:" + "p" * 100 + "@h.example/x?y") == f"https://u:{R}@h.example/x?y"


def test_endpoint_with_method():
    assert endpoint("GET https://u:pw@h.example/v1") == f"GET https://u:{R}@h.example/v1"
