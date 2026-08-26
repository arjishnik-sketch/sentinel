"""Offline tests for the NOMINATE stage (app.tools.nominate).

The nominator DRIVES proof-assist tools (sqlmap first) and adapts their output
into ``source="tool"`` hypotheses — but a tool NEVER confirms; the pure judge
still disposes downstream. These pin the honest floor: OFF by default, trust only
a real injection-point report, scope + shape discipline, and fault tolerance. The
subprocess is an injected ``run`` seam, so nothing here spawns a process.
"""
import types

from app.autonomous import orchestrator as O
from app.autonomous.hypotheses import Hypothesis
from app.autonomous.surface import Surface
from app.tools import nominate as N


# A realistic sqlmap stdout: the injection-point banner + one Parameter block.
SQLMAP_HIT = """
[*] starting @ 12:00:00
[INFO] testing connection to the target URL
[INFO] testing if GET parameter 'id' is dynamic
sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1
---
[*] ending @ 12:00:09
"""

# sqlmap ran but found nothing — no injection-point banner. We trust NOTHING.
SQLMAP_NONE = """
[INFO] testing connection to the target URL
[WARNING] GET parameter 'id' does not seem to be injectable
[*] ending @ 12:00:09
"""


def _res(stdout):
    return types.SimpleNamespace(stdout=stdout, stderr="", returncode=0)


def _plan(hyps, target="http://shop.test"):
    return O.Plan(surface=Surface(target=target), hypotheses=tuple(hyps))


# ---- parse: trust only a real injection-point report ------------------------

def test_parse_sqlmap_extracts_nominated_get_param():
    hyps = N.parse_sqlmap(SQLMAP_HIT, url="http://shop.test/item?id=1")
    assert len(hyps) == 1
    h = hyps[0]
    assert (h.technique, h.method, h.param, h.location, h.source) == (
        "sql_injection", "GET", "id", "query", "tool")
    assert h.url == "http://shop.test/item?id=1"
    assert h.provable  # goes through the differential judge like any hypothesis


def test_parse_sqlmap_post_maps_to_body_form():
    text = SQLMAP_HIT.replace("Parameter: id (GET)", "Parameter: email (POST)")
    hyps = N.parse_sqlmap(text, url="http://shop.test/login")
    assert [(h.method, h.location) for h in hyps] == [("POST", "body_form")]


def test_parse_sqlmap_without_hit_marker_trusts_nothing():
    assert N.parse_sqlmap(SQLMAP_NONE, url="http://shop.test/item?id=1") == []


def test_parse_sqlmap_skips_unsupported_location():
    # A COOKIE/URI nomination is honestly dropped until that location lands E2E.
    text = SQLMAP_HIT.replace("Parameter: id (GET)", "Parameter: TrackingId (COOKIE)")
    assert N.parse_sqlmap(text, url="http://shop.test/") == []


# ---- nominate: OFF by default, gated, adapts, fault-tolerant ----------------

def test_nominate_off_by_default_runs_nothing(monkeypatch):
    monkeypatch.delenv("SENTINEL_ENABLE_TOOLS", raising=False)
    calls = []
    plan = _plan([Hypothesis("sql_injection", "http://shop.test/item?id=1",
                             "GET", "id", "query")])
    out = N.nominate(plan, run=lambda *a, **k: calls.append(a) or _res(SQLMAP_HIT))
    assert out == [] and calls == []          # no consent → no tool touched


def test_nominate_enabled_drives_sqlmap_and_adapts():
    calls = []

    def fake_run(tool, args, **k):
        calls.append((tool, tuple(args)))
        return _res(SQLMAP_HIT)

    plan = _plan([Hypothesis("sql_injection", "http://shop.test/item?id=1",
                             "GET", "id", "query")])
    out = N.nominate(plan, enabled=True, run=fake_run)
    assert calls and calls[0][0] == "sqlmap"
    assert "-u" in calls[0][1] and "http://shop.test/item?id=1" in calls[0][1]
    assert [h.source for h in out] == ["tool"]
    assert out[0].technique == "sql_injection" and out[0].param == "id"


def test_nominate_enabled_via_env(monkeypatch):
    monkeypatch.setenv("SENTINEL_ENABLE_TOOLS", "1")
    plan = _plan([Hypothesis("sql_injection", "http://shop.test/item?id=1",
                             "GET", "id", "query")])
    out = N.nominate(plan, run=lambda *a, **k: _res(SQLMAP_HIT))
    assert len(out) == 1 and out[0].source == "tool"


def test_nominate_only_targets_get_query_sqli():
    calls = []

    def fake_run(tool, args, **k):
        calls.append(tuple(args))
        return _res("")

    # A POST-body SQLi + a GET XSS: neither is a GET-query SQLi target for sqlmap.
    plan = _plan([
        Hypothesis("sql_injection", "http://shop.test/login", "POST", "email", "body_json"),
        Hypothesis("xss", "http://shop.test/item?q=1", "GET", "q", "query"),
    ])
    assert N.nominate(plan, enabled=True, run=fake_run) == []
    assert calls == []                        # nothing GET-query-SQLi → sqlmap idle


def test_nominate_swallows_tool_faults():
    def boom(*a, **k):
        raise RuntimeError("sqlmap not installed")

    plan = _plan([Hypothesis("sql_injection", "http://shop.test/item?id=1",
                             "GET", "id", "query")])
    assert N.nominate(plan, enabled=True, run=boom) == []   # never crashes the loop
