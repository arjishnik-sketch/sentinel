"""NOMINATE — the "tools propose" half made real.

The selector (:mod:`app.tools.selector`) decides WHICH curated tools to bring to
bear; this module DRIVES the proof-assist ones and adapts their raw output back
into :class:`~app.autonomous.hypotheses.Hypothesis` proposals. A tool run here
NEVER produces a verdict: sqlmap saying "param X is injectable" becomes a
``source="tool"`` hypothesis that the SAME pure differential judge must reproduce
downstream. A tool hit is a LEAD until the judge disposes it — trusting a tool's
own "finding" is the analogue of manufacturing a verdict, and is forbidden.

Safety envelope (defense in depth):
  * OFF by default — the whole stage no-ops unless ``$SENTINEL_ENABLE_TOOLS`` is
    truthy (or ``enabled=True`` is passed). A normal ``autonomous`` run behaves
    exactly as before: no external exploitation tool is executed.
  * Install stays approval-gated by ``runner.ensure_available`` (``_deny``
    default) — no tool is silently installed.
  * Every emitted hypothesis is scope-filtered to the observed host and shape-
    deduped, so a nomination can never wander off-target or issue a probe the
    plan already carries.
  * Fault-tolerant — a flaky/absent tool is skipped, never crashes the loop.

The heavy edge (``runner.run_tool``) is an injectable ``run`` seam, so the whole
module is exercised offline in tests with zero subprocess / network.
"""
from __future__ import annotations

import os
import re
from urllib.parse import urlsplit

from app.autonomous.hypotheses import Hypothesis
from app.tools import runner as _runner
from app.tools.selector import select_tools

_TRUTHY = {"1", "true", "yes", "y", "on"}

# Keep tool runs bounded — nominate the most-relevant candidate URLs, not the
# entire crawl. A large surface still costs a fixed, predictable number of runs.
_MAX_TARGETS = 10

# sqlmap prints this banner immediately before the injection-point blocks. We
# trust a `Parameter:` line ONLY when it follows this marker — never parse params
# out of sqlmap's chatty progress log.
_SQLMAP_HIT = "identified the following injection point"
_SQLMAP_PARAM = re.compile(
    r"^\s*Parameter:\s*(?P<name>[^\s(]+)\s*\((?P<method>[A-Za-z]+)\)"
)


def _truthy(val) -> bool:
    return (val or "").strip().lower() in _TRUTHY


def parse_sqlmap(text, *, url):
    """Forgiving parse of sqlmap stdout → ``source="tool"`` SQLi hypotheses.

    Returns [] unless sqlmap actually reported an injection point (the hit marker
    is present); then one hypothesis per distinct ``Parameter: <name> (<METHOD>)``
    block. Only GET/POST are mapped (query / body_form) — a COOKIE/URI nomination
    is honestly skipped until those locations land end-to-end. The URL is the one
    we drove sqlmap against, so it anchors the differential the judge re-runs."""
    text = text or ""
    if _SQLMAP_HIT not in text.lower():
        return []
    out, seen = [], set()
    for line in text.splitlines():
        m = _SQLMAP_PARAM.match(line)
        if not m:
            continue
        name = m.group("name").strip()
        method = m.group("method").upper()
        if not name or method not in ("GET", "POST") or (name, method) in seen:
            continue
        seen.add((name, method))
        location = "body_form" if method == "POST" else "query"
        out.append(Hypothesis(
            "sql_injection", url, method, name, location,
            rationale=f"sqlmap nominated {method} param '{name}' (judge re-proves)",
            severity="HIGH", source="tool"))
    return out


# ---- per-tool drivers -------------------------------------------------------
# Each driver takes (plan, run, approve) and returns raw ``source="tool"``
# hypotheses; scope/dedup is applied centrally by :func:`nominate`. A conservative
# argv keeps the run bounded and non-destructive (bounded level/risk, batch mode
# so nothing is interactive, no coloring so stdout stays parseable).

def _sqli_get_targets(plan):
    """Distinct GET query URLs (with a concrete param) already in the plan — the
    surface sqlmap should probe. sqlmap only NOMINATES; even a duplicate of a
    rule-floor hypothesis is harmless (dedup drops it), and a param sqlmap flags
    that the floor missed is exactly the widening we want."""
    urls, seen = [], set()
    for h in plan.hypotheses:
        if h.technique != "sql_injection" or (h.method or "GET").upper() != "GET":
            continue
        if h.location != "query" or not h.param or h.url in seen:
            continue
        seen.add(h.url)
        urls.append(h.url)
        if len(urls) >= _MAX_TARGETS:
            break
    return urls


def _sqlmap_argv(url):
    return ("-u", url, "--batch", "--level=1", "--risk=1",
            "--technique=BT", "--disable-coloring")


def _drive_sqlmap(plan, *, run, approve):
    out = []
    for url in _sqli_get_targets(plan):
        try:
            res = run("sqlmap", _sqlmap_argv(url), approve=approve)
        except Exception:
            continue  # missing / declined / flaky tool: skip, never crash
        out.extend(parse_sqlmap(getattr(res, "stdout", "") or "", url=url))
    return out


_DRIVERS = {"sqlmap": _drive_sqlmap}


# ---- the stage --------------------------------------------------------------

def _dedup_scope(hyps, surface):
    host = surface.host
    seen, out = set(), []
    for h in hyps:
        raw = h.url if "://" in (h.url or "") else "http://" + (h.url or "")
        netloc = urlsplit(raw).netloc.lower()
        if host and netloc and netloc != host:
            continue  # a nomination can never wander off the observed host
        if h.shape in seen:
            continue
        seen.add(h.shape)
        out.append(h)
    return out


def nominate(plan, *, enabled=None, run=None, approve=None):
    """Run approval-gated proof-assist tools as NOMINATORS over ``plan``.

    Returns a list of ``source="tool"`` hypotheses to fold into the plan (via
    :func:`app.autonomous.orchestrator.augment_plan`) so the pure judges dispose
    them like any other proposal. OFF unless ``enabled`` (or
    ``$SENTINEL_ENABLE_TOOLS``) is truthy. Never raises."""
    if enabled is None:
        enabled = _truthy(os.environ.get("SENTINEL_ENABLE_TOOLS"))
    if not enabled:
        return []
    run = run or _runner.run_tool
    try:
        tool_plan = select_tools(plan.surface, plan.hypotheses)
    except Exception:
        return []
    raw = []
    for rec in tool_plan.assist():
        driver = _DRIVERS.get(rec.name)
        if driver is None:
            continue  # no driver for this proposer yet (e.g. dalfox — roadmap)
        try:
            raw.extend(driver(plan, run=run, approve=approve))
        except Exception:
            continue  # a driver fault must never break the loop
    return _dedup_scope(raw, plan.surface)
