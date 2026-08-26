"""Offline tests for the proof-carrying report generator (app.autonomous.report).

Zero network, zero LLM. We drive :func:`build_report` with real orchestrator
``Verdict`` objects and faithfully-shaped fakes for the JudgeEvidence / proven
graph / remediation outcome, then assert the report ASSERTS NOTHING it was not
handed: proofs are the judge's own words, steps are the literal recorded probes,
sensitive header values are masked, remediation flips render, tiers stay honest,
JSON is deterministic, and the LLM narration seam is advisory-only and safe.
"""
from __future__ import annotations

import json
from types import SimpleNamespace as NS

import pytest

from app.autonomous import orchestrator as O
from app.autonomous import report as R
from app.autonomous.hypotheses import Hypothesis


# ---- faithfully-shaped fakes (attribute shapes match the real objects) ------

def _req(method, url, headers=(), body=""):
    return NS(method=method, url=url, headers=tuple(headers), body=body)


def _exp(exp_id, hyp_id, action, request, evidence_ids=()):
    return NS(id=exp_id, hypothesis_id=hyp_id, action=action, request=request,
              evidence_ids=tuple(evidence_ids))


def _confirmed_evidence():
    """A JudgeEvidence-like object with the fresh graph a real judge proves on."""
    url = "http://shop.test/login?id=1"
    experiments = {
        # deliberately out of order + a sensitive Cookie header to exercise sort+redaction
        "exp:injection-true-0:h1": _exp(
            "exp:injection-true-0:h1", "h1", "probe_injection_true-0",
            _req("GET", "http://shop.test/login?id=1%20OR%201=1",
                 headers=(("Cookie", "session=SECRETVALUE"), ("Accept", "*/*"))),
            evidence_ids=("ev:2",)),
        "exp:injection-baseline:h1": _exp(
            "exp:injection-baseline:h1", "h1", "probe_injection_baseline",
            _req("GET", url), evidence_ids=("ev:1",)),
        "exp:injection-false-0:h1": _exp(
            "exp:injection-false-0:h1", "h1", "probe_injection_false-0",
            _req("GET", "http://shop.test/login?id=1%20OR%201=2"), evidence_ids=("ev:3",)),
    }
    finding = NS(id="find:1", hypothesis_id="h1", title="SQL injection in login id",
                 severity="CRITICAL", evidence_ids=("ev:1", "ev:2", "ev:3"))
    graph = NS(experiments=experiments, findings={"find:1": finding})
    result = NS(hypothesis_id="h1", status="VALIDATED",
                reason="boolean pair toggled the backend query")
    check = NS(baseline_value="1", param="id", method="GET", location="query")
    policy = NS(checks=(check,))
    return NS(technique="sql_injection", status="VALIDATED",
              reason="boolean pair toggled the backend query",
              target_base="http://shop.test", graph=graph, policy=policy, result=result)


def _fix_proven_outcome():
    plan = NS(rule=NS(method="GET", path="/login", param="id", location="query"),
              rationale=("parameterize the query", "reject non-numeric id"))
    ver = NS(before_status="VALIDATED", after_status="DISPROVED", proven=True,
             before_status_code=200, observed_status_code=403)
    artifacts = NS(nginx="location /login { deny_sqli; }", portable_json='{"rule":"id"}')
    return NS(finding_id="find:1", hypothesis_id="h1", result="FIX_PROVEN",
              plan=plan, verification=ver, artifacts=artifacts, detail="remediation proven")


def _report_with_all_tiers():
    confirmed = O.Verdict(
        Hypothesis("sql_injection", "http://shop.test/login?id=1", "GET", "id", "query",
                   "resource id in path", "CRITICAL", "rule"),
        O.VERDICT_CONFIRMED, detail="confirmed", evidence=_confirmed_evidence())
    lead = O.Verdict(
        Hypothesis("idor", "http://shop.test/api/users/2", "GET", "id", "path",
                   "sequential id", "HIGH", "llm"),
        O.VERDICT_LEAD, detail="no judge wired; surfaced as lead")
    disproved = O.Verdict(
        Hypothesis("xss", "http://shop.test/s?q=x", "GET", "q", "query", "", "MEDIUM"),
        O.VERDICT_DISPROVED, detail="no reflection differential")
    inconclusive = O.Verdict(
        Hypothesis("ssrf", "http://shop.test/fetch?u=x", "GET", "u", "query"),
        O.VERDICT_INCONCLUSIVE, detail="no anchor")
    errored = O.Verdict(
        Hypothesis("cors", "http://shop.test/api", "GET"),
        O.VERDICT_ERROR, detail="judge raised: boom")
    surface = NS(target="http://shop.test", host="shop.test",
                 endpoints=("a", "b", "c"), params=("id", "q"),
                 techs=("nginx", "node"), has_login=True, has_graphql=False,
                 has_swagger=False, has_uploads=False, is_spa=True)
    plan = NS(surface=surface)
    return NS(plan=plan, verdicts=(confirmed, lead, disproved, inconclusive, errored))


# ---- build_report: tiers + counts -------------------------------------------

def test_build_report_tiers_and_counts():
    model = R.build_report(_report_with_all_tiers(), outcomes=(_fix_proven_outcome(),),
                           generated_at="2026-08-25T00:00:00+00:00")
    assert model.counts == {"confirmed": 1, "leads": 1, "disproved": 1,
                            "inconclusive": 1, "errors": 1, "fix_proven": 1}
    assert len(model.findings) == 1 and len(model.leads) == 1
    assert model.host == "shop.test"
    assert model.surface["endpoints"] == 3 and model.surface["parameters"] == 2
    assert "login" in model.surface["signals"] and "spa" in model.surface["signals"]


# ---- proof is the judge's own words, never invented -------------------------

def test_confirmed_finding_carries_judge_proof():
    model = R.build_report(_report_with_all_tiers(), generated_at="t")
    f = model.findings[0]
    assert f.technique == "sql_injection" and f.severity == "CRITICAL"
    assert f.proof.judge == "judge_sql_injection"
    assert f.proof.judge_status == "VALIDATED"          # judge word, not "CONFIRMED"
    assert f.proof.reason == "boolean pair toggled the backend query"
    assert f.proof.anchor == "1"                        # the benign differential anchor
    assert f.proof.evidence_ids == ("ev:1", "ev:2", "ev:3")


# ---- steps are the literal probes, baseline first ---------------------------

def test_steps_are_recorded_probes_baseline_first():
    model = R.build_report(_report_with_all_tiers(), generated_at="t")
    steps = model.findings[0].steps
    assert [s.ordinal for s in steps] == [1, 2, 3]
    assert steps[0].arm == "baseline"                   # baseline/control sort first
    assert {s.arm for s in steps} == {"baseline", "false-0", "true-0"}


# ---- sensitive header VALUES are masked in the deliverable ------------------

def test_sensitive_header_values_are_redacted():
    model = R.build_report(_report_with_all_tiers(), generated_at="t")
    md = R.render_markdown(model)
    assert "SECRETVALUE" not in md                      # the captured session never leaks
    assert R._MASK in md
    assert "Accept: */*" in md                          # non-sensitive header preserved verbatim


# ---- remediation flip renders (VALIDATED -> DISPROVED, proven) --------------

def test_remediation_flip_renders():
    model = R.build_report(_report_with_all_tiers(), outcomes=(_fix_proven_outcome(),),
                           generated_at="t")
    rem = model.findings[0].remediation
    assert rem is not None and rem.result == "FIX_PROVEN" and rem.proven is True
    md = R.render_markdown(model)
    assert "VALIDATED → DISPROVED" in md and "✓ proven" in md
    assert "FIX_PROVEN" in md
    assert "nginx" in rem.artifacts


def test_no_remediation_renders_honestly():
    model = R.build_report(_report_with_all_tiers(), generated_at="t")  # no outcomes
    assert model.findings[0].remediation is None
    md = R.render_markdown(model)
    assert "not run" in md.lower()


# ---- JSON is deterministic, complete, and carries the deployable config -----

def test_render_json_is_deterministic_and_complete():
    model = R.build_report(_report_with_all_tiers(), outcomes=(_fix_proven_outcome(),),
                           generated_at="t")
    a = R.render_json(model)
    b = R.render_json(model)
    assert a == b                                       # byte-identical
    doc = json.loads(a)
    assert doc["counts"]["confirmed"] == 1
    # the full deployable config text lives in the JSON record, not just its name
    configs = doc["findings"][0]["remediation"]["configs"]
    assert any("deny_sqli" in text for _name, text in configs)


# ---- write_report persists both artifacts -----------------------------------

def test_write_report_persists_both(tmp_path):
    model = R.build_report(_report_with_all_tiers(), outcomes=(_fix_proven_outcome(),),
                           generated_at="t")
    arts = R.write_report(model, out_dir=str(tmp_path))
    assert arts.stem == "shop-test"
    md_text = (tmp_path / "shop-test.md").read_text(encoding="utf-8")
    js_text = (tmp_path / "shop-test.json").read_text(encoding="utf-8")
    assert md_text == arts.markdown and js_text == arts.json
    assert "# Sentinel" in md_text
    assert json.loads(js_text)["host"] == "shop.test"


# ---- narration seam: advisory-only, safe, and leak-free ---------------------

def test_narrate_returns_empty_without_seam():
    model = R.build_report(_report_with_all_tiers(), generated_at="t")
    assert R.narrate(model, complete=None) == ""


def test_narrate_uses_seam_and_never_leaks_captured_data():
    model = R.build_report(_report_with_all_tiers(), generated_at="t")
    seen = {}

    def complete(prompt):
        seen["prompt"] = prompt
        return "  Confirmed a critical SQLi in the login id parameter.  "

    prose = R.narrate(model, complete=complete)
    assert prose == "Confirmed a critical SQLi in the login id parameter."
    # the narrator is shown metadata only — never the captured session/response bytes
    assert "SECRETVALUE" not in seen["prompt"]
    assert "sql_injection" in seen["prompt"]


def test_narrate_swallows_seam_failure():
    model = R.build_report(_report_with_all_tiers(), generated_at="t")

    def boom(_prompt):
        raise RuntimeError("llm down")

    assert R.narrate(model, complete=boom) == ""       # a flaky LLM never breaks the report


def test_narrative_is_fenced_as_advisory_in_markdown():
    model = R.build_report(_report_with_all_tiers(), generated_at="t")
    md = R.render_markdown(model, narrative="An executive overview.")
    assert "advisory" in md.lower()
    assert "An executive overview." in md


# ---- empty report renders without crashing ----------------------------------

def test_empty_report_renders():
    empty = NS(plan=NS(surface=NS(target="http://x.test", host="x.test",
                                  endpoints=(), params=(), techs=())),
               verdicts=())
    model = R.build_report(empty, generated_at="t")
    assert model.counts["confirmed"] == 0
    md = R.render_markdown(model)
    assert "No differential reproduced" in md
    json.loads(R.render_json(model))                    # valid JSON even when empty
