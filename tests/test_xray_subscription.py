import base64

from migate.xray.subscription import build_base64_subscription, normalize_subscription_links


def test_normalize_subscription_links_removes_empty_items_and_strips_whitespace():
    links = normalize_subscription_links([" vless://a ", "", "\n", "trojan://b"])

    assert links == ["vless://a", "trojan://b"]


def test_build_base64_subscription_encodes_links_line_by_line():
    result = build_base64_subscription(["vless://a", "trojan://b", "ss://c"])

    decoded = base64.b64decode(result).decode()
    assert decoded == "vless://a\ntrojan://b\nss://c"


def test_build_base64_subscription_returns_empty_string_for_no_links():
    assert build_base64_subscription(["", "  "]) == ""
