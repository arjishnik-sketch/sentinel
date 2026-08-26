"""Proof-carrying report generator — the deliverable at the end of the loop.

The autonomous loop finishes with an :class:`orchestrator.Report` (a plan + tiered
verdicts) and, when the operator approved the deploy gate, a list of remediation
outcomes. This module turns that evidence into the report the user asked for: per
CONFIRMED finding, the literal steps to reproduce, the proof, and the remediation
with its VALIDATED->DISPROVED flip — plus honest LEADs and the tested-safe results.

CONTRACT, preserved here: this module ASSERTS NOTHING of its own. Every claim it
prints is lifted verbatim from what a pure judge already proved — the judge's own
reason, the differential arms it actually issued (recorded as experiments on the
graph it proved on), the evidence ids, and the remediation verdict. It opens no
socket and re-probes nothing. An optional LLM narration layer may add prose, but
it is fenced as advisory and never contributes a fact; the machine-readable record
stands entirely on the graph-backed evidence. Facts the graph does not carry are
omitted, never invented — the analogue, once more, of never manufacturing a verdict.

Pure and deterministic: given the same report + outcomes it emits byte-identical
markdown/JSON (the timestamp is the only injected input), so it is offline-testable.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

from . import orchestrator as O

# Request headers whose VALUE may carry a captured-session secret (the session-aware
# stage forwards a real Cookie/Authorization). We keep the header NAME so the
# reproduction is faithful, but mask the value — a report is a deliverable that gets
# shared, and echoing a live credential into it is exactly the secret leak the
# safety contract forbids.
_SENSITIVE_HEADERS = frozenset({
    "cookie", "set-cookie", "authorization", "proxy-authorization",
    "x-api-key", "x-auth-token", "x-csrf-token",
})
_MASK = "‹redacted›"
_MAX_BODY = 512
_MAX_EVIDENCE_IDS = 24
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_ARTIFACT_PROVIDERS = ("nginx", "modsecurity", "envoy_rbac", "caddy", "portable_json")


# ---- small pure helpers -----------------------------------------------------

def _clip(text, limit):
    text = "" if text is None else str(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _sev_rank(severity):
    return _SEVERITY_ORDER.get((severity or "").upper(), 4)


def _redact_headers(headers):
    """Header tuples with sensitive VALUES masked (names preserved)."""
    out = []
    for item in headers or ():
        try:
            name, value = item
        except (ValueError, TypeError):
            continue
        masked = _MASK if str(name).lower() in _SENSITIVE_HEADERS else str(value)
        out.append((str(name), masked))
    return tuple(out)


# ---- the report record shapes (all DATA; JSON-serialisable via asdict) ------

@dataclass(frozen=True)
class ReproStep:
    ordinal: int
    arm: str                 # the judge's own probe tag: baseline / true-0 / oddquote-0 …
    method: str
    url: str
    headers: tuple = ()
    body: str = ""


@dataclass(frozen=True)
class Proof:
    technique: str
    judge: str               # e.g. judge_sql_injection
    judge_status: str        # the judge's own word (VALIDATED) before the CONFIRMED label
    reason: str              # verbatim judge reason — the proof narrative
    anchor: str = ""         # benign baseline value grounding the differential
    evidence_ids: tuple = ()


@dataclass(frozen=True)
class RemediationRecord:
    result: str              # FIX_PROVEN / FIX_FAILED / NOT_APPLICABLE / ERROR / not-run
    control: str = ""
    before_status: str = ""  # the judge's pre-fix verdict (VALIDATED)
    after_status: str = ""   # the same judge under live enforcement (DISPROVED)
    proven: bool = False
    before_status_code: object = None
    observed_status_code: object = None
    rationale: tuple = ()
    detail: str = ""
    artifacts: tuple = ()    # provider names that were rendered
    configs: tuple = ()      # ((provider, deployable_config_text), …) — full text in JSON


@dataclass(frozen=True)
class FindingRecord:
    technique: str
    title: str
    severity: str
    method: str
    url: str
    param: str
    location: str
    target_base: str
    finding_id: str
    proof: Proof
    steps: tuple = ()
    remediation: object = None       # RemediationRecord | None


@dataclass(frozen=True)
class LeadRecord:
    technique: str
    severity: str
    method: str
    url: str
    param: str
    rationale: str
    source: str
    detail: str


@dataclass(frozen=True)
class OtherRecord:
    """A DISPROVED / INCONCLUSIVE / ERROR verdict, shown honestly."""
    status: str
    technique: str
    method: str
    url: str
    param: str
    detail: str


@dataclass(frozen=True)
class ReportModel:
    target: str
    host: str
    generated_at: str
    surface: dict
    counts: dict
    findings: tuple = ()
    leads: tuple = ()
    disproved: tuple = ()
    inconclusive: tuple = ()
    errors: tuple = ()


# ---- evidence extraction (graph-backed; never invents a fact) ---------------

def _arm_of(experiment):
    """The judge's own arm tag for one recorded probe (baseline / true-0 / …)."""
    action = getattr(experiment, "action", "") or ""
    if action.startswith("probe_"):
        action = action[len("probe_"):]
    if "_" in action:                     # "injection_baseline" -> "baseline"
        head, tail = action.split("_", 1)
        action = tail or head
    return action or _clip(getattr(experiment, "id", "") or "probe", 48)


def _arm_rank(arm):
    a = (arm or "").lower()
    return 0 if ("baseline" in a or "control" in a) else 1


def _steps_from_graph(graph, hypothesis_id):
    """Every reproducible probe the judge issued, as literal HTTP requests. The
    graph a judge proved on holds exactly this hypothesis's experiments (each judge
    runs on a fresh graph), so we reconstruct the steps — we never fabricate one."""
    experiments = list(getattr(graph, "experiments", {}).values()) if graph else []
    if hypothesis_id:
        scoped = [e for e in experiments if getattr(e, "hypothesis_id", None) == hypothesis_id]
        experiments = scoped or experiments
    experiments = [e for e in experiments if getattr(e, "request", None) is not None]
    experiments.sort(key=lambda e: (_arm_rank(_arm_of(e)), getattr(e, "id", "")))
    steps = []
    for i, exp in enumerate(experiments, start=1):
        req = exp.request
        body = getattr(req, "body", None)
        steps.append(ReproStep(
            ordinal=i,
            arm=_arm_of(exp),
            method=getattr(req, "method", "") or "GET",
            url=getattr(req, "url", "") or "",
            headers=_redact_headers(getattr(req, "headers", ()) or ()),
            body=_clip(body, _MAX_BODY) if body else "",
        ))
    return tuple(steps)


def _check_of(evidence):
    policy = getattr(evidence, "policy", None)
    checks = getattr(policy, "checks", None) or ()
    return checks[0] if checks else None


def _finding_for(evidence):
    graph = getattr(evidence, "graph", None)
    findings = list(getattr(graph, "findings", {}).values()) if graph else []
    if not findings:
        return None
    hyp_id = getattr(getattr(evidence, "result", None), "hypothesis_id", None)
    if hyp_id:
        match = [f for f in findings if getattr(f, "hypothesis_id", None) == hyp_id]
        if match:
            findings = match
    return sorted(findings, key=lambda f: getattr(f, "id", ""))[0]


def _evidence_ids(evidence, finding):
    ids = list(getattr(finding, "evidence_ids", ()) or []) if finding else []
    if not ids:
        graph = getattr(evidence, "graph", None)
        for exp in (getattr(graph, "experiments", {}).values() if graph else ()):
            ids.extend(getattr(exp, "evidence_ids", ()) or ())
    return tuple(sorted(dict.fromkeys(ids))[:_MAX_EVIDENCE_IDS])


def _proof_of(verdict):
    """The Proof, plus the finding/check we recovered (reused by the record builder)."""
    evidence = verdict.evidence
    technique = getattr(evidence, "technique", None) or verdict.hypothesis.technique
    finding = _finding_for(evidence)
    check = _check_of(evidence)
    anchor = getattr(check, "baseline_value", "") if check is not None else ""
    reason = getattr(evidence, "reason", "") or verdict.detail or ""
    proof = Proof(
        technique=technique,
        judge=f"judge_{technique}",
        judge_status=getattr(evidence, "status", "") or "VALIDATED",
        reason=reason,
        anchor=anchor or "",
        evidence_ids=_evidence_ids(evidence, finding),
    )
    return proof, finding, check


def _control_line(plan):
    rule = getattr(plan, "rule", None)
    if rule is None:
        return getattr(plan, "strategy", "") or ""
    method, path = getattr(rule, "method", ""), getattr(rule, "path", "")
    param, location = getattr(rule, "param", ""), getattr(rule, "location", "")
    bits = [f"{method} {path}".strip()]
    if param:
        bits.append(f"guard '{param}'" + (f" ({location})" if location else ""))
    return " · ".join(b for b in bits if b)


def _artifacts(outcome):
    art = getattr(outcome, "artifacts", None)
    names, configs = [], []
    if art is not None:
        for prov in _ARTIFACT_PROVIDERS:
            text = getattr(art, prov, None)
            if text:
                names.append(prov)
                configs.append((prov, text))
    return tuple(names), tuple(configs)


def _remediation_of(outcome):
    if outcome is None:
        return None
    plan = getattr(outcome, "plan", None)
    ver = getattr(outcome, "verification", None)
    names, configs = _artifacts(outcome)
    return RemediationRecord(
        result=getattr(outcome, "result", "") or "",
        control=_control_line(plan) if plan is not None else "",
        before_status=getattr(ver, "before_status", "") if ver is not None else "",
        after_status=getattr(ver, "after_status", "") if ver is not None else "",
        proven=bool(getattr(ver, "proven", False)) if ver is not None else False,
        before_status_code=getattr(ver, "before_status_code", None) if ver is not None else None,
        observed_status_code=getattr(ver, "observed_status_code", None) if ver is not None else None,
        rationale=tuple(getattr(plan, "rationale", ()) or ()) if plan is not None else (),
        detail=_clip(getattr(outcome, "detail", ""), 400),
        artifacts=names,
        configs=configs,
    )


# ---- per-verdict record builders --------------------------------------------

def _confirmed_record(verdict, outcomes_by_finding):
    proof, finding, check = _proof_of(verdict)
    hyp = verdict.hypothesis
    evidence = verdict.evidence
    hyp_id = getattr(getattr(evidence, "result", None), "hypothesis_id", None)

    title = (getattr(finding, "title", "") if finding is not None else "") or \
        f"{proof.technique} at {hyp.param or hyp.url}"
    severity = ((getattr(finding, "severity", "") if finding is not None else "")
                or getattr(hyp, "severity", "") or "HIGH").upper()
    finding_id = getattr(finding, "id", "") if finding is not None else ""
    outcome = outcomes_by_finding.get(finding_id) if finding_id else None

    return FindingRecord(
        technique=proof.technique,
        title=title,
        severity=severity,
        method=(hyp.method or getattr(check, "method", "") or "GET"),
        url=hyp.url,
        param=(hyp.param or getattr(check, "param", "") or ""),
        location=(getattr(hyp, "location", "") or getattr(check, "location", "") or ""),
        target_base=getattr(evidence, "target_base", "") or "",
        finding_id=finding_id,
        proof=proof,
        steps=_steps_from_graph(getattr(evidence, "graph", None), hyp_id),
        remediation=_remediation_of(outcome),
    )


def _lead_record(verdict):
    hyp = verdict.hypothesis
    return LeadRecord(
        technique=hyp.technique,
        severity=(getattr(hyp, "severity", "") or "").upper(),
        method=hyp.method or "GET",
        url=hyp.url,
        param=hyp.param or "",
        rationale=_clip(getattr(hyp, "rationale", ""), 300),
        source=getattr(hyp, "source", "") or "",
        detail=_clip(verdict.detail, 200),
    )


def _other_record(verdict):
    hyp = verdict.hypothesis
    return OtherRecord(
        status=verdict.status,
        technique=hyp.technique,
        method=hyp.method or "GET",
        url=hyp.url,
        param=hyp.param or "",
        detail=_clip(verdict.detail, 300),
    )


def _surface_summary(plan):
    surface = getattr(plan, "surface", None)
    if surface is None:
        return {}
    signals = [name for name, on in (
        ("login", getattr(surface, "has_login", False)),
        ("graphql", getattr(surface, "has_graphql", False)),
        ("swagger", getattr(surface, "has_swagger", False)),
        ("uploads", getattr(surface, "has_uploads", False)),
        ("spa", getattr(surface, "is_spa", False)),
    ) if on]
    return {
        "host": getattr(surface, "host", "") or "",
        "endpoints": len(getattr(surface, "endpoints", ()) or ()),
        "parameters": len(getattr(surface, "params", ()) or ()),
        "tech": list(getattr(surface, "techs", ()) or ()),
        "signals": signals,
    }


# ---- build: verdicts (+ outcomes) -> a proof-carrying model -----------------

def build_report(report, *, outcomes=(), target=None, generated_at=None):
    """Assemble a :class:`ReportModel` from an orchestrator report and the (optional)
    remediation outcomes. Pure: sorts everything deterministically, opens nothing."""
    plan = getattr(report, "plan", None)
    surface = getattr(plan, "surface", None)
    target = target or getattr(surface, "target", "") or getattr(surface, "host", "") or ""
    host = getattr(surface, "host", "") or urlsplit(
        target if "://" in (target or "") else f"http://{target or ''}").netloc

    outcomes_by_finding = {}
    for outcome in outcomes or ():
        outcomes_by_finding.setdefault(getattr(outcome, "finding_id", "") or "", outcome)

    findings, leads, disproved, inconclusive, errors = [], [], [], [], []
    for verdict in getattr(report, "verdicts", ()) or ():
        status = getattr(verdict, "status", "")
        if status == O.VERDICT_CONFIRMED and getattr(verdict, "evidence", None) is not None:
            findings.append(_confirmed_record(verdict, outcomes_by_finding))
        elif status == O.VERDICT_LEAD:
            leads.append(_lead_record(verdict))
        elif status == O.VERDICT_DISPROVED:
            disproved.append(_other_record(verdict))
        elif status == O.VERDICT_INCONCLUSIVE:
            inconclusive.append(_other_record(verdict))
        else:                                  # ERROR, or a CONFIRMED without evidence
            errors.append(_other_record(verdict))

    findings.sort(key=lambda f: (_sev_rank(f.severity), f.technique, f.url, f.param))
    leads.sort(key=lambda r: (_sev_rank(r.severity), r.technique, r.url, r.param))
    for rows in (disproved, inconclusive, errors):
        rows.sort(key=lambda r: (r.technique, r.url, r.param))

    counts = {
        "confirmed": len(findings), "leads": len(leads), "disproved": len(disproved),
        "inconclusive": len(inconclusive), "errors": len(errors),
        "fix_proven": sum(1 for f in findings
                          if f.remediation is not None and f.remediation.result == "FIX_PROVEN"),
    }
    if generated_at is None:
        generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    return ReportModel(
        target=target, host=host, generated_at=generated_at,
        surface=_surface_summary(plan), counts=counts,
        findings=tuple(findings), leads=tuple(leads), disproved=tuple(disproved),
        inconclusive=tuple(inconclusive), errors=tuple(errors),
    )


# ---- markdown rendering (human deliverable) ---------------------------------

def _md_steps(steps):
    lines = []
    for step in steps:
        lines.append(f"{step.ordinal}. **{step.arm}** — `{step.method} {step.url}`")
        for name, value in step.headers:
            lines.append(f"   - {name}: {value}")
        if step.body:
            lines.append(f"   - body: `{step.body}`")
    return "\n".join(lines)


def _md_remediation(rem):
    if rem is None:
        return "**Remediation** — _not run (deploy gate not reached or declined)._"
    lines = ["**Remediation**", "", f"- result: **{rem.result or 'not-run'}**"]
    if rem.control:
        lines.append(f"- corrective control: {rem.control}")
    if rem.before_status or rem.after_status:
        flip = f"{rem.before_status or '?'} → {rem.after_status or '?'}"
        lines.append(f"- same pure judge under live enforcement: **{flip}**"
                     + ("  ✓ proven" if rem.proven else ""))
    if rem.before_status_code is not None or rem.observed_status_code is not None:
        lines.append(f"- http: {rem.before_status_code} → {rem.observed_status_code}")
    for reason in rem.rationale:
        lines.append(f"  - {reason}")
    if rem.artifacts:
        lines.append(f"- deployable configs rendered: {', '.join(rem.artifacts)} "
                     "(full text in the JSON report)")
    if rem.detail and not (rem.before_status or rem.after_status):
        lines.append(f"- detail: {rem.detail}")
    return "\n".join(lines)


def _md_finding(f):
    out = [f"### {f.severity} · {f.title}", ""]
    out.append(f"- **technique**: {f.technique}")
    out.append(f"- **endpoint**: `{f.method} {f.url}`")
    if f.param:
        out.append(f"- **parameter**: `{f.param}`" + (f" ({f.location})" if f.location else ""))
    if f.finding_id:
        out.append(f"- **finding id**: `{f.finding_id}`")
    out += ["", "**Steps to reproduce** — the exact probes the pure judge issued:", ""]
    out.append(_md_steps(f.steps) or "_(no recorded probes)_")
    out += ["", "**Proof**", ""]
    out.append(f"- judge: `{f.proof.judge}` → **{f.proof.judge_status}** "
               "(the orchestrator labels this CONFIRMED)")
    if f.proof.anchor:
        out.append(f"- differential anchor (benign baseline): `{f.proof.anchor}`")
    if f.proof.reason:
        out.append(f"- reason: {f.proof.reason}")
    if f.proof.evidence_ids:
        out.append("- evidence: " + ", ".join(f"`{e}`" for e in f.proof.evidence_ids))
    out += ["", _md_remediation(f.remediation), ""]
    return "\n".join(out)


def render_markdown(model, *, narrative=""):
    c = model.counts
    L = [
        "# Sentinel — Autonomous Pentest Report",
        "",
        f"**Target:** {model.target}  ",
        f"**Generated:** {model.generated_at}  ",
        f"**Result:** {c['confirmed']} confirmed · {c['fix_proven']} fix-proven · "
        f"{c['leads']} leads · {c['disproved']} tested-safe",
        "",
        "> Contract: the LLM and tools only propose; a pure differential judge disposes. "
        "Every CONFIRMED finding below is a reproduced differential with an explicit anchor "
        "— never a bare status. Nothing was deployed without the operator's approval.",
        "",
    ]
    if narrative:
        L += ["## Summary (advisory narration)", "",
              "_LLM-written overview. Advisory only — every load-bearing claim is in the "
              "evidence-backed sections below._", "", narrative.strip(), ""]

    surface = model.surface
    if surface:
        L += ["## Surface", "",
              f"- host: `{surface.get('host', '')}`",
              f"- endpoints: {surface.get('endpoints', 0)} · "
              f"parameters: {surface.get('parameters', 0)}"]
        if surface.get("tech"):
            L.append(f"- tech: {', '.join(surface['tech'])}")
        if surface.get("signals"):
            L.append(f"- signals: {', '.join(surface['signals'])}")
        L.append("")

    L += [f"## Confirmed findings ({len(model.findings)})", ""]
    if model.findings:
        for finding in model.findings:
            L.append(_md_finding(finding))
    else:
        L += ["_No differential reproduced. Nothing is claimed as confirmed._", ""]

    if model.leads:
        L += [f"## Leads ({len(model.leads)})", "",
              "Honest, evidence-backed directions with no single-probe differential "
              "judge — never conflated with a proof.", ""]
        for lead in model.leads:
            L.append(f"- **{lead.technique}** `{lead.method} {lead.url}`"
                     + (f" param `{lead.param}`" if lead.param else "")
                     + (f" — {lead.rationale}" if lead.rationale else ""))
        L.append("")

    if model.disproved:
        L += [f"## Tested safe ({len(model.disproved)})", "",
              "The judge ran the differential and it did NOT reproduce — a compliant "
              "control, reported for completeness.", ""]
        for row in model.disproved:
            L.append(f"- **{row.technique}** `{row.method} {row.url}`"
                     + (f" param `{row.param}`" if row.param else ""))
        L.append("")

    for title, rows in (("Inconclusive", model.inconclusive), ("Errors", model.errors)):
        if rows:
            L += [f"## {title} ({len(rows)})", ""]
            for row in rows:
                L.append(f"- **{row.technique}** `{row.method} {row.url}`"
                         + (f" — {row.detail}" if row.detail else ""))
            L.append("")

    L += ["---", "",
          "_Generated by Sentinel. Steps-to-reproduce are the literal probes recorded on "
          "the graph each pure judge proved on; proofs are the judge's own verdicts and "
          "evidence ids. This report asserts nothing beyond what was proven._"]
    return "\n".join(L) + "\n"


# ---- JSON rendering (machine-readable record) -------------------------------

def to_dict(model):
    """The full model as plain JSON-safe dicts — every proof, step, evidence id and
    rendered remediation config included, so the JSON is the authoritative record."""
    return asdict(model)


def render_json(model):
    return json.dumps(to_dict(model), indent=2, ensure_ascii=False) + "\n"


# ---- write both artifacts to disk -------------------------------------------

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slug(text, *, default="report"):
    slug = _SLUG_RE.sub("-", (text or "").lower()).strip("-")
    return slug[:60] or default


@dataclass(frozen=True)
class ReportArtifacts:
    """Where the deliverables landed — returned so the CLI can point the user at them."""
    stem: str
    markdown_path: str
    json_path: str
    markdown: str
    json: str


def write_report(model, *, out_dir="reports", stem=None, narrative=""):
    """Render markdown + JSON and persist both. Returns :class:`ReportArtifacts`.

    The only side effect in this module: it touches disk. Pure rendering stays in
    :func:`render_markdown` / :func:`render_json` so tests can assert on text with no
    filesystem at all."""
    stem = stem or _slug(model.host or model.target)
    md = render_markdown(model, narrative=narrative)
    js = render_json(model)
    os.makedirs(out_dir, exist_ok=True)
    md_path = os.path.join(out_dir, f"{stem}.md")
    js_path = os.path.join(out_dir, f"{stem}.json")
    with open(md_path, "w", encoding="utf-8") as handle:
        handle.write(md)
    with open(js_path, "w", encoding="utf-8") as handle:
        handle.write(js)
    return ReportArtifacts(stem=stem, markdown_path=md_path, json_path=js_path,
                           markdown=md, json=js)


# ---- optional LLM narration (advisory prose only, never a fact) -------------

def _digest(model):
    """A compact, metadata-only digest of what was proven — the ONLY thing the
    narrator is shown. No response bodies, no captured credentials, no raw probe
    payloads cross into the prompt: the narrator gets facts-about-findings, never
    the target's data."""
    lines = [f"target={model.target}", f"host={model.host}",
             f"counts={model.counts}"]
    for f in model.findings:
        rem = f.remediation.result if f.remediation is not None else "none"
        lines.append(f"CONFIRMED {f.severity} {f.technique} at "
                     f"{f.method} {f.url} param={f.param or '-'} remediation={rem}")
    for lead in model.leads:
        lines.append(f"LEAD {lead.technique} at {lead.method} {lead.url}")
    return "\n".join(lines)


def narrate(model, *, complete=None):
    """Advisory executive summary via an injected completion seam ``complete(prompt)``.

    Returns ``""`` when no seam is supplied (the offline default) OR when the seam
    fails — the report must render fully without ever depending on an LLM. The prose
    it returns is fenced as advisory by :func:`render_markdown`; it contributes no
    fact, exactly as the LLM only ever proposes and never disposes."""
    if complete is None:
        return ""
    prompt = (
        "You are writing the executive summary of a web application penetration test. "
        "Below is a metadata-only digest of findings a deterministic judge already "
        "PROVED. Write 3-6 sentences for a technical stakeholder: what was confirmed, "
        "the business risk, and the remediation posture. Do not invent findings, "
        "severities, or numbers beyond the digest. Plain prose, no markdown headers.\n\n"
        f"{_digest(model)}\n"
    )
    try:
        text = complete(prompt)
    except Exception:
        return ""
    return (text or "").strip()









