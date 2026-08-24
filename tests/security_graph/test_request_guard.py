"""
Generalised request-guard (Phase 0 of ROADMAP.md §5).

One guard, many families. These tests lock the pluggable-signature-family
behaviour of ``RequestGuardRule`` / ``evaluate_request_guard`` so every future
class (ssti, xss, traversal, url_allowlist, jwt) inherits a proven virtual-patch
seam. The SQLi family + its back-compat shim must stay identical.

Network-free: all pure functions, no sockets.
"""

import base64
import json

from app.security_graph.remediation.enforcer import (
    RequestGuardRule,
    _matches_signature,
    _matches_sqli_signature,
    _resolve_family,
    evaluate_request_guard,
)

SEARCH = "/rest/products/search"


def _guard(**kw):
    kw.setdefault("method", "GET")
    kw.setdefault("path", SEARCH)
    return RequestGuardRule(**kw)


# --------------------------------------------------------------------------- #
# Back-compat: the SQLi family and its shim are unchanged.
# --------------------------------------------------------------------------- #
def test_sqli_family_backcompat():
    assert _matches_sqli_signature("apple' OR '1'='1")
    assert _matches_sqli_signature("1 UNION SELECT password FROM users")
    assert not _matches_sqli_signature("green tea 500ml")
    # default family is sqli
    assert _matches_signature("apple' OR '1'='1", "") is True
    assert _matches_signature("apple' OR '1'='1", "sqli") is True


def test_default_signature_family_is_sqli():
    rule = _guard(param="q")  # no signature_family
    assert rule.signature_family == "sqli"
    assert evaluate_request_guard("GET", SEARCH, "q=apple", None, (rule,)) == "forward"
    assert (
        evaluate_request_guard("GET", SEARCH, "q=apple'+OR+'1'%3D'1", None, (rule,))
        == "deny"
    )


# --------------------------------------------------------------------------- #
# SSTI family.
# --------------------------------------------------------------------------- #
def test_ssti_family_matches_template_delimiters():
    for payload in ("{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{% raw %}"):
        assert _matches_signature(payload, "ssti"), payload
    assert not _matches_signature("hello world", "ssti")
    assert not _matches_signature("price is 49", "ssti")


def test_ssti_family_alias_resolves():
    assert _resolve_family("template_injection") == "ssti"
    assert _matches_signature("{{7*7}}", "template_injection")


def test_ssti_guard_denies_only_template_payload():
    rule = _guard(param="name", signature_family="ssti")
    assert evaluate_request_guard("GET", SEARCH, "name=widget", None, (rule,)) == "forward"
    assert (
        evaluate_request_guard("GET", SEARCH, "name=%7B%7B7*7%7D%7D", None, (rule,))
        == "deny"
    )


# --------------------------------------------------------------------------- #
# XSS family.
# --------------------------------------------------------------------------- #
def test_xss_family_matches_breakout_shapes():
    for payload in (
        "<script>alert(1)</script>",
        '"><svg/onload=alert(1)>',
        "x' onerror=alert(1)",
        "javascript:alert(1)",
    ):
        assert _matches_signature(payload, "xss"), payload
    assert not _matches_signature("perfectly normal comment", "xss")


# --------------------------------------------------------------------------- #
# Path-traversal family.
# --------------------------------------------------------------------------- #
def test_traversal_family_matches_escape_shapes():
    for payload in (
        "../../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "%2e%2e%2fetc%2fpasswd",
        "file\x00.png",
    ):
        assert _matches_signature(payload, "traversal"), payload
    assert not _matches_signature("report-2026.pdf", "traversal")


# --------------------------------------------------------------------------- #
# url_allowlist family — INVERTED (deny off-origin unless host is allowed).
# --------------------------------------------------------------------------- #
def test_url_allowlist_denies_offorigin_allows_listed():
    allow = ("app.example.com",)
    assert _matches_signature("https://evil.attacker/", "url_allowlist", allow) is True
    assert _matches_signature("https://app.example.com/next", "url_allowlist", allow) is False
    # relative path / same-origin — no host, never blocked
    assert _matches_signature("/dashboard", "url_allowlist", allow) is False
    assert _matches_signature("", "url_allowlist", allow) is False


def test_url_allowlist_guard_end_to_end():
    rule = _guard(param="next", signature_family="url_allowlist", allow=("app.example.com",))
    assert (
        evaluate_request_guard("GET", SEARCH, "next=%2Fhome", None, (rule,)) == "forward"
    )
    assert (
        evaluate_request_guard(
            "GET", SEARCH, "next=https%3A%2F%2Fevil.attacker%2F", None, (rule,)
        )
        == "deny"
    )


# --------------------------------------------------------------------------- #
# JWT family — deny alg=none / unsigned; forward a real signed token.
# --------------------------------------------------------------------------- #
def _b64(obj) -> str:
    raw = json.dumps(obj).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def test_jwt_family_denies_forgeries_forwards_signed():
    none_tok = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64({'sub': 'admin'})}."
    unsigned = f"{_b64({'alg': 'HS256'})}.{_b64({'sub': 'x'})}"  # 2-part, no sig
    signed = f"{_b64({'alg': 'HS256'})}.{_b64({'sub': 'x'})}.c2lnbmF0dXJl"

    assert _matches_signature(none_tok, "jwt") is True
    assert _matches_signature(unsigned, "jwt") is True
    assert _matches_signature(signed, "jwt") is False
    # tolerate a Bearer wrapper
    assert _matches_signature(f"Bearer {none_tok}", "jwt") is True
    # non-jwt values are never matched
    assert _matches_signature("just-a-string", "jwt") is False


def test_unknown_family_never_matches():
    assert _matches_signature("anything", "does_not_exist") is False
