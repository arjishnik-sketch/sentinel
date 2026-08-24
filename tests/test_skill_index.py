"""Offline tests for the security-skills KB index (no external checkout needed)."""
import pytest

from app.knowledge import skill_index as SI


def test_parse_frontmatter_reads_yaml_block():
    text = (
        "---\n"
        "name: demo-skill\n"
        "description: A web SQL injection tester.\n"
        "domain: cybersecurity\n"
        "subdomain: web-security\n"
        "tags:\n- web\n- sql-injection\n"
        "mitre_attack:\n- T1190\n"
        "---\n## Workflow\nnothing here\n"
    )
    fm = SI.parse_frontmatter(text)
    assert fm["name"] == "demo-skill"
    assert fm["tags"] == ["web", "sql-injection"]
    assert fm["mitre_attack"] == ["T1190"]


def test_parse_frontmatter_no_block_is_empty():
    assert SI.parse_frontmatter("## no frontmatter\n") == {}


def _idx():
    return SI.SkillIndex.from_dicts([
        {"name": "web-sqli", "description": "SQL injection in web apps",
         "subdomain": "web-security", "tags": ["web", "sql-injection", "injection"]},
        {"name": "ad-kerberoast", "description": "Kerberoasting Active Directory",
         "subdomain": "red-teaming", "tags": ["active-directory", "kerberos"]},
        {"name": "web-auth", "description": "Session and login testing",
         "subdomain": "web-security", "tags": ["authentication", "session", "login"]},
    ])


def test_select_ranks_by_overlap_and_drops_zero_score():
    res = _idx().select(["web", "injection"])
    assert res and res[0].name == "web-sqli"
    assert all(c.name != "ad-kerberoast" for c in res)  # zero-score dropped


def test_select_respects_limit_and_is_deterministic():
    idx = _idx()
    first = [c.name for c in idx.select(["web"], limit=1)]
    again = [c.name for c in idx.select(["web"], limit=1)]
    assert len(first) == 1 and first == again


def test_surface_terms_base_plus_flags_plus_tech_deduped():
    class S:
        techs = ("React",)
        has_login = True
        has_graphql = False
        has_swagger = False
        has_uploads = False
        is_spa = True
    terms = SI.surface_terms(S())
    assert "web" in terms                      # base bias
    assert "authentication" in terms           # has_login
    assert "javascript" in terms               # is_spa
    assert "react" in terms                     # tech token, lowercased
    assert len(terms) == len(set(terms))       # de-duplicated


def test_select_for_surface_prefers_web_auth_over_host():
    class LoginSurface:
        techs = ()
        has_login = True
        has_graphql = False
        has_swagger = False
        has_uploads = False
        is_spa = False
    picked = {c.name for c in _idx().select_for_surface(LoginSurface())}
    assert "web-auth" in picked
    assert "ad-kerberoast" not in picked


def test_from_json_missing_raises_but_load_never_does():
    with pytest.raises(OSError):
        SI.SkillIndex.from_json("/no/such/skill_index.json")
    idx = SI.SkillIndex.load()          # swallows failures, always returns an index
    assert isinstance(idx, SI.SkillIndex)


def test_packaged_index_present_and_web_relevant():
    idx = SI.SkillIndex.load()
    assert len(idx) > 100               # the committed 817-card index
    class ApiSurface:
        techs = ("Express",)
        has_login = True
        has_graphql = True
        has_swagger = True
        has_uploads = False
        is_spa = False
    assert idx.select_for_surface(ApiSurface(), limit=5)  # non-empty, relevant
