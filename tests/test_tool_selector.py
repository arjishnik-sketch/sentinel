"""Offline tests for the tool-selection module (app.tools.selector).

Pure DATA layer: no network, no real tools, no installs. These prove the SELECTION
logic — broad-vs-technique-gated scoring, deterministic ordering, the
propose-only invariant, and the approval-gated install hand-off.
"""
import types

from app.tools import selector as S
from app.tools.resolver import InstallRecipe


def _surface(**flags):
    return types.SimpleNamespace(**flags)


def _hyp(technique):
    return types.SimpleNamespace(technique=technique)


# ---- registry integrity -----------------------------------------------------

def test_every_tool_is_propose_only():
    # The hard invariant: no tool in the registry may ever be a verdict source.
    assert S.TOOL_REGISTRY and all(t.proposes_only for t in S.TOOL_REGISTRY.values())


def test_registry_roles_are_known():
    known = {S.ROLE_RECON, S.ROLE_DISCOVERY, S.ROLE_FINGERPRINT,
             S.ROLE_PROOF_ASSIST, S.ROLE_SECRETS, S.ROLE_MANUAL}
    assert all(t.role in known for t in S.TOOL_REGISTRY.values())


# ---- broad tools apply with no hypotheses -----------------------------------

def test_recon_tools_recommended_without_hypotheses():
    plan = S.select_tools(_surface())
    names = plan.names
    assert "httpx" in names and "katana" in names and "subfinder" in names
    # broad tools have a positive score and a reason
    assert all(r.score >= 1 and r.reasons for r in plan.recon())


# ---- technique-gated proof-assist tools -------------------------------------

def test_sqlmap_gated_off_without_sqli_hypothesis():
    # No SQLi hypothesis in play → we never propose a SQLi tool (honest scoping).
    plan = S.select_tools(_surface(), hypotheses=[_hyp("xss")])
    assert "sqlmap" not in plan.names
    assert "dalfox" in plan.names            # xss hypothesis → its proposer appears


def test_sqlmap_proposed_with_sqli_hypothesis():
    plan = S.select_tools(_surface(), hypotheses=[_hyp("sql_injection")])
    assert "sqlmap" in plan.names
    rec = plan.for_technique("sql_injection")
    assert rec and rec[0].name == "sqlmap"
    assert any("assists sql_injection" in r for r in rec[0].reasons)
    # a technique match outscores a broad recon tool
    assert rec[0].score > plan.recon()[0].score


def test_proof_assist_outranks_broad_but_recon_leads_ties():
    # Deterministic order: higher score first, then role phase, then name.
    plan = S.select_tools(_surface(), hypotheses=[_hyp("sql_injection"), _hyp("xss")])
    scores = [r.score for r in plan.recommendations]
    assert scores == sorted(scores, reverse=True)     # non-increasing
    assist_names = [r.name for r in plan.assist()]
    assert assist_names == ["dalfox", "sqlmap"]        # both present, name-sorted


# ---- install hand-off (approval-gated downstream) ---------------------------

def test_installable_excludes_manual_and_unknown_recipes():
    plan = S.select_tools(_surface(), hypotheses=[_hyp("sql_injection")])
    installable = {r.name for r in plan.installable()}
    assert "burpsuite" not in installable            # manual-only, never auto-run
    assert "httpx" in installable and "sqlmap" in installable


def test_recommendation_install_recipe_lookup():
    plan = S.select_tools(_surface())
    httpx = next(r for r in plan.recommendations if r.name == "httpx")
    assert isinstance(httpx.install, InstallRecipe) and httpx.install.command[0] == "go"
    burp = next((r for r in plan.recommendations if r.name == "burpsuite"), None)
    assert burp is not None and burp.install is None  # no recipe → operator-driven


def test_manual_tool_present_but_segregated():
    plan = S.select_tools(_surface())
    assert "burpsuite" in plan.names
    assert [r.name for r in plan.manual()] == ["burpsuite"]
