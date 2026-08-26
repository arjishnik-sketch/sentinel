"""Offline tests for the `autonomous <target>` command (app.commands.autonomous_cmd).

The command's live edges — recon, the differential judges, the KB, the deploy
gate — are all injectable seams, so the whole loop is exercised here with zero
network / Ollama / tools. These prove the WIRING (recon→plan→prove→patch gate),
never the real judges (which have their own live-proven suites).
"""
import app.commands.autonomous_cmd as A
from app.autonomous import orchestrator as O
from app.autonomous.hypotheses import Hypothesis


# ---- shared fakes -----------------------------------------------------------

RECON = {"target": "http://shop.test", "crawl": ["http://shop.test/item?id=1"],
         "alive": [{"tech": []}]}
FINDINGS = {"parameters": ["id"], "logins": [], "javascript": [], "graphql": [],
            "swagger": [], "uploads": [], "apis": []}


class FakeGraph:
    """A stand-in for the graph a judge proved on. ``findings`` is what
    ``findings_for`` yields for the matching (kind, OPEN)."""

    def __init__(self, findings=()):
        self._findings = list(findings)

    def findings_for(self, kind=None, status=None):
        return [f for f in self._findings
                if (kind is None or f.kind == kind)
                and (status is None or f.status == status)]


class FakeFinding:
    def __init__(self, fid, kind, title="t", severity="HIGH", status="OPEN"):
        self.id = self.finding_id = fid
        self.kind = kind
        self.title = title
        self.severity = severity
        self.status = status


class FakeEvidence:
    def __init__(self, graph):
        self.graph = graph


def _v(technique, status, *, graph=None):
    return O.Verdict(Hypothesis(technique, "http://shop.test/item?id=1", param="id"),
                     status, detail="", evidence=FakeEvidence(graph) if graph else None)


# ---- grouping ---------------------------------------------------------------

def test_group_confirmed_only_and_ordered():
    verdicts = [
        _v("xss", O.VERDICT_DISPROVED),
        _v("sql_injection", O.VERDICT_CONFIRMED),
        _v("ssrf", O.VERDICT_CONFIRMED),
        _v("sql_injection", O.VERDICT_CONFIRMED),
        _v("path_traversal", O.VERDICT_LEAD),
    ]
    grouped = A._group_confirmed(verdicts)
    assert [t for t, _g in grouped] == ["sql_injection", "ssrf"]   # first-seen order
    assert len(dict(grouped)["sql_injection"]) == 2


# ---- control-line recipes (exact per-class shapes) --------------------------

def test_control_line_recipes_match_class_shapes():
    class Rule:
        param, location, method, path = "id", "query", "GET", "/x"
        allow_host, allow_netloc = "shop.test", "shop.test:80"

    class Plan:
        rule = Rule()

    p = Plan()
    assert A._ctl_request_guard(p) == "request-guard id (query) → GET /x"
    assert A._ctl_open_redirect(p) == "request-guard id (query) → allow-host shop.test"
    assert A._ctl_cors(p) == "strip ACAO/ACAC on GET /x"
    assert A._ctl_ssrf(p) == "deny off-allowlist fetch on GET /x ?id"


# ---- PATCH→PROVE stage (fake registry + fake gate) --------------------------

def _rem_spec(remediate_calls, *, synth_plan="PLAN"):
    def synth(graph, finding):
        return synth_plan

    def remediate(graph):
        remediate_calls.append(graph)
        return [type("O", (), {"result": "FIX_PROVEN", "verification": None,
                               "detail": "", "finding_id": "f1"})()]

    return A._RemSpec(kind="injection", label="sql injection", synth=synth,
                      remediate=remediate, control=lambda p: f"ctl:{p}",
                      fallback_control="fallback")


def test_remediate_confirmed_gates_then_remediates_the_proven_graph():
    graph = FakeGraph([FakeFinding("f1", "injection", title="SQLi", severity="HIGH")])
    verdicts = [_v("sql_injection", O.VERDICT_CONFIRMED, graph=graph)]
    calls, gate_seen = [], []

    def gate(label, proposals):
        gate_seen.append((label, tuple(p.control for p in proposals)))
        return True

    outcomes = A._remediate_confirmed(
        verdicts, registry={"sql_injection": _rem_spec(calls)}, gate=gate)

    assert gate_seen == [("sql injection", ("ctl:PLAN",))]   # synth→control shown
    assert calls == [graph]                                  # remediated the SAME graph
    assert outcomes and outcomes[0].result == "FIX_PROVEN"


def test_remediate_declined_gate_does_not_remediate():
    graph = FakeGraph([FakeFinding("f1", "injection")])
    calls = []
    outcomes = A._remediate_confirmed(
        [_v("sql_injection", O.VERDICT_CONFIRMED, graph=graph)],
        registry={"sql_injection": _rem_spec(calls)}, gate=lambda l, p: False)
    assert calls == [] and outcomes == []


def test_remediate_skips_confirmed_without_a_graph():
    calls = []
    outcomes = A._remediate_confirmed(
        [_v("sql_injection", O.VERDICT_CONFIRMED, graph=None)],
        registry={"sql_injection": _rem_spec(calls)}, gate=lambda l, p: True)
    assert calls == [] and outcomes == []          # no graph → nothing to patch


def test_remediate_honors_skip_env(monkeypatch):
    monkeypatch.setenv("SENTINEL_SKIP_REMEDIATION", "1")
    graph = FakeGraph([FakeFinding("f1", "injection")])
    calls = []
    outcomes = A._remediate_confirmed(
        [_v("sql_injection", O.VERDICT_CONFIRMED, graph=graph)],
        registry={"sql_injection": _rem_spec(calls)}, gate=lambda l, p: True)
    assert calls == [] and outcomes == []


# ---- session-aware stage ----------------------------------------------------

class _FakeProber:
    def __init__(self, decide):
        self.decide = decide
        self.calls = []

    def request(self, method, url, *, headers=None, body=None):
        from app.autonomous.probe import Probe
        cookie = (headers or {}).get("Cookie", "")
        self.calls.append((method, url, cookie))
        return Probe(method, url, self.decide(url, cookie), {}, (), "")


def test_session_stage_off_without_cookie(monkeypatch):
    monkeypatch.delenv("SENTINEL_SESSION_COOKIE", raising=False)
    plan = O.build_plan(RECON, FINDINGS, use_llm=False)
    assert A._session_stage(plan.surface, plan) is None


def test_session_stage_bisects_and_panel_renders():
    plan = O.build_plan(RECON, FINDINGS, use_llm=False)
    prober = _FakeProber(lambda url, cookie: 200 if "sid=" in cookie else 401)
    sm = A._session_stage(plan.surface, plan, cookie="sid=abc; theme=dark",
                          session_url="http://shop.test/item?id=1", prober=prober)
    assert sm is not None
    assert sm.cookie_report.load_bearing == ("sid",)
    assert set(sm.cookie_report.placeholders) == {"theme"}
    A._session_panel(sm)          # must not raise


# ---- end-to-end (offline) ---------------------------------------------------

def test_run_end_to_end_offline_is_tiered(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)   # report writes land under tmp, not the repo
    proven = FakeGraph()          # confirmed, but no OPEN finding → no live patch
    judges = {
        "sql_injection": lambda h, p=None: ("VALIDATED", "boolean toggled",
                                            FakeEvidence(proven)),
        "xss": lambda h, p=None: ("DISPROVED", "escaped", None),
    }
    report = A.run("http://shop.test", _recon=lambda t: (RECON, FINDINGS),
                   _index=None, _judges=judges, use_llm=False)

    assert isinstance(report, O.Report)
    by = {v.hypothesis.technique: v.status for v in report.verdicts}
    assert by["sql_injection"] == O.VERDICT_CONFIRMED
    assert by["xss"] == O.VERDICT_DISPROVED
    assert by["path_traversal"] == O.VERDICT_LEAD      # provable, un-wired here
    assert report.confirmed and report.confirmed[0].hypothesis.technique == "sql_injection"


def test_run_writes_proof_carrying_report(tmp_path, monkeypatch):
    """Stage 10 is wired: a completed run persists a markdown + json report whose
    facts come only from the verdicts (LLM off → no narration seam)."""
    monkeypatch.chdir(tmp_path)
    judges = {
        "sql_injection": lambda h, p=None: ("VALIDATED", "boolean toggled",
                                            FakeEvidence(FakeGraph())),
    }
    A.run("http://shop.test", _recon=lambda t: (RECON, FINDINGS),
          _index=None, _judges=judges, use_llm=False)

    reports = tmp_path / "reports"
    mds = list(reports.glob("*.md"))
    jsons = list(reports.glob("*.json"))
    assert mds and jsons, "run() must persist a markdown + json report"
    text = mds[0].read_text(encoding="utf-8")
    assert "sql_injection" in text                     # the confirmed technique
    assert "advisory narration" not in text.lower()    # LLM off → no narration section
    import json as _json
    data = _json.loads(jsons[0].read_text(encoding="utf-8"))
    assert data["counts"]["confirmed"] >= 1


def test_run_empty_target_prints_usage_and_returns_none():
    assert A.run("") is None


# ---- Stage 2 + Stage 5 wiring (offline) -------------------------------------

def test_run_attaches_endpoint_selection_and_plans_execution(tmp_path, monkeypatch):
    """A full offline run threads Stage 2 (endpoint selection on the plan) and
    Stage 5 (execution shape) — the new panels render without raising."""
    monkeypatch.chdir(tmp_path)
    judges = {"sql_injection": lambda h, p=None: ("DISPROVED", "escaped", None)}
    report = A.run("http://shop.test", _recon=lambda t: (RECON, FINDINGS),
                   _index=None, _judges=judges, use_llm=False)
    assert isinstance(report, O.Report)
    sel = report.plan.endpoint_selection
    assert sel is not None and sel.total >= 1 and not sel.pruned


def test_run_honors_endpoint_budget_env(tmp_path, monkeypatch):
    """$SENTINEL_ENDPOINT_BUDGET focuses coverage on the top-N endpoints."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SENTINEL_ENDPOINT_BUDGET", "1")
    recon = {"target": "http://shop.test",
             "crawl": ["http://shop.test/item?id=1", "http://shop.test/plain"],
             "alive": [{"tech": []}]}
    findings = dict(FINDINGS)
    report = A.run("http://shop.test", _recon=lambda t: (recon, findings),
                   _index=None, _judges={}, use_llm=False)
    assert report.plan.endpoint_selection.pruned
    assert len(report.plan.surface.endpoints) == 1


def test_run_with_tools_enabled_renders_execplan_tools(tmp_path, monkeypatch):
    """With $SENTINEL_ENABLE_TOOLS on, the PLAN EXECUTION panel lists in-scope
    proof-assist tools (data only; the injected no-op nominator runs no tool)."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SENTINEL_ENABLE_TOOLS", "1")
    report = A.run("http://shop.test", _recon=lambda t: (RECON, FINDINGS),
                   _index=None, _judges={}, _nominate=lambda plan, approve=None: [],
                   use_llm=False)
    assert isinstance(report, O.Report)   # tools-enabled panel branch renders cleanly


# ---- NOMINATE end-to-end (tool proposes → augment_plan → judge disposes) -----

def test_run_folds_tool_nomination_and_judge_confirms_it(tmp_path, monkeypatch):
    """The full NOMINATE path: an injected tool nominator widens the plan with a
    source="tool" hypothesis on a surface the rule floor never posed, and the SAME
    pure judge then disposes it. A tool proposes; the judge confirms — never the
    tool. Proves tool → augment_plan → judge, end-to-end and offline."""
    monkeypatch.chdir(tmp_path)
    tool_hyp = Hypothesis("sql_injection", "http://shop.test/api?cat=1", "GET",
                          "cat", "query", severity="HIGH", source="tool")

    def nominate(plan, approve=None):
        return [tool_hyp]

    # Validate ONLY the tool-nominated shape → isolates the fold-in as the cause.
    def sqli_judge(h, p=None):
        if h.source == "tool":
            return ("VALIDATED", "boolean toggled", FakeEvidence(FakeGraph()))
        return ("DISPROVED", "escaped", None)

    report = A.run("http://shop.test", _recon=lambda t: (RECON, FINDINGS),
                   _index=None, _judges={"sql_injection": sqli_judge},
                   _nominate=nominate, use_llm=False)

    assert any(h.source == "tool" for h in report.plan.hypotheses)   # nomination folded in
    tool_verdicts = [v for v in report.verdicts if v.hypothesis.source == "tool"]
    assert tool_verdicts, "the tool nomination must be judged like any hypothesis"
    v = tool_verdicts[0]
    assert v.status == O.VERDICT_CONFIRMED                            # judge (not tool) confirmed
    assert v.hypothesis.technique == "sql_injection" and v.hypothesis.param == "cat"


def test_run_nominate_seam_faults_degrade_to_unaugmented_plan(tmp_path, monkeypatch):
    """A flaky nominator never sinks the run — the loop proceeds on the plan as-is."""
    monkeypatch.chdir(tmp_path)

    def boom(plan, approve=None):
        raise RuntimeError("sqlmap exploded")

    report = A.run("http://shop.test", _recon=lambda t: (RECON, FINDINGS),
                   _index=None, _judges={}, _nominate=boom, use_llm=False)

    assert isinstance(report, O.Report)
    assert not any(h.source == "tool" for h in report.plan.hypotheses)
