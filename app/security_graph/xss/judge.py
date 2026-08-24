"""
PURE deterministic judge for the reflected-XSS class.

The analogue of :func:`judge_template_injection`, but it reasons over a
**reflection differential** rather than an arithmetic one. Given a hypothesis,
the id of a *control* probe (a benign random marker with no HTML-significant
characters) and the ids of one or more *payload* probes (that same marker
wrapped in active-markup breakout shapes — ``<script>``, ``<svg onload=>``,
``<img onerror=>``, ``<body onload=>``), it recovers the operator-declared
surface and the seeded marker the seeder wrote into the graph, reads the observed
response-body text of each probe, and decides:

  VALIDATED     some payload response contains the raw payload markup VERBATIM
                (the ``<tag`` and the marker inside it survived un-escaped) AND
                the control proved the app reflects the bare marker — so the
                HTML-significant characters ``<``/``>`` provably passed through
                output encoding untouched (a real reflected XSS);
  DISPROVED     no payload's raw markup survived verbatim — the parameter is
                HTML-escaped (``&lt;script&gt;``), stripped, or dropped, never
                reflected as active markup (also the post-fix state once the
                request-guard blocks the breakout shapes);
  INCONCLUSIVE  the control probe evidence is missing/unreadable, or a payload's
                raw markup already appears in the control response (its anchor is
                contaminated — that markup is on the page independent of our
                injection), or no payload probe was readable, or the surface
                metadata is missing.

Three things make this sound. First, a status code alone is never the verdict —
only the verbatim survival of the raw ``<tag>`` markup in the body is. Second,
the marker embedded INSIDE the payload means a verbatim match cannot be produced
by markup that was already on the page — it can only be OUR reflected input, and
an app that HTML-escapes the input turns ``<script>`` into ``&lt;script&gt;``,
which is not a substring of the raw payload. Third, the control anchors the
differential: it proves the app reflects the bare marker (so the parameter
reaches the body) and that the raw markup is not already present, so a raw ``<tag>``
appearing only under a payload is attributable to un-escaped reflection and not
to coincidence. The judge has no target knowledge, performs no scoring, and never
mutates the graph.

Scope (stated honestly): this proves the load-bearing precondition of reflected
XSS — attacker-controlled *active markup* reflected UN-escaped into the response.
It does not model the DOM execution context (e.g. reflection inside a comment or
``<textarea>``), so it is deliberately CONSERVATIVE: it never claims blind or
DOM-only XSS, and any output-encoding fix collapses it to DISPROVED.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..graph import SecurityGraph
from ..models import Hypothesis, ValidationJudgment
from .xss_policy import marker_payloads


@dataclass(frozen=True)
class XSSExpectation:
    """The declared reflected-XSS surface + seeded marker for one identity."""

    method: str
    path: str
    endpoint_url: str
    param: str
    location: str
    marker: str
    severity: str


def xss_expectation(
    graph: SecurityGraph,
    *,
    resource_id: str,
    aspect: str,
) -> XSSExpectation | None:
    """
    Recover the declared reflected-XSS surface for one hypothesis identity.

    `aspect` is the identity action; it keys onto the
    ``requires_no_reflected_xss`` relationship the seeder emitted. Returns None
    if no matching edge exists (or the seeded marker is missing).
    """
    target = f"xss:{aspect}"
    for relationship in graph.relationships:
        if (
            relationship.source == resource_id
            and relationship.relation == "requires_no_reflected_xss"
            and relationship.target == target
        ):
            meta = dict(relationship.metadata)
            marker = meta.get("marker", "")
            if not marker:
                return None
            return XSSExpectation(
                method=meta.get("method", "GET"),
                path=meta.get("path", ""),
                endpoint_url=meta.get("endpoint_url", ""),
                param=meta.get("param", ""),
                location=meta.get("location", "query"),
                marker=marker,
                severity=meta.get("severity", "HIGH"),
            )
    return None


def _probe_evidence(graph: SecurityGraph, experiment):
    """The single HTTP probe evidence backing this experiment, or None."""
    if experiment is None:
        return None
    candidates = []
    for evidence_id in experiment.evidence_ids:
        evidence = graph.evidence.get(evidence_id)
        if evidence is None:
            continue
        data = evidence.data
        if (
            isinstance(data, dict)
            and data.get("mode") == "http"
            and "status_code" in data
            and "response_body_text" in data
        ):
            candidates.append(evidence)
    if len(candidates) != 1:
        return None
    return candidates[0]


def _probe_body(graph: SecurityGraph, experiment_id: str | None):
    """(response_body_text, evidence_id) for a probe, or None if unreadable."""
    if experiment_id is None:
        return None
    evidence = _probe_evidence(graph, graph.experiments.get(experiment_id))
    if evidence is None:
        return None
    body = evidence.data.get("response_body_text")
    if not isinstance(body, str):
        return None
    return body, evidence.id


def judge_reflected_xss(
    graph: SecurityGraph,
    *,
    hypothesis: Hypothesis,
    control_experiment_id: str,
    payload_experiment_ids: tuple[tuple[str, str], ...],
) -> ValidationJudgment:
    """Decide whether the reflection differential proves a reflected XSS.

    ``payload_experiment_ids`` is a tuple of ``(label, experiment_id)`` pairs;
    each payload probe wrapped the SAME benign marker in a different active-markup
    breakout shape.
    """

    identity = hypothesis.identity
    if identity is None or not (identity.resource_id and identity.action):
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=control_experiment_id,
            status="INCONCLUSIVE",
            reason="hypothesis lacks a resource/aspect identity",
            contradiction_kind="xss",
        )

    expectation = xss_expectation(
        graph,
        resource_id=identity.resource_id,
        aspect=identity.action,
    )
    if expectation is None or not expectation.param:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=control_experiment_id,
            status="INCONCLUSIVE",
            reason="no declared reflected-XSS surface (or seeded marker) for this hypothesis",
            contradiction_kind="xss",
        )

    marker = expectation.marker
    payloads = dict(marker_payloads(marker))

    control = _probe_body(graph, control_experiment_id)
    if control is None:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=control_experiment_id,
            status="INCONCLUSIVE",
            reason="the control probe evidence is missing or unreadable",
            contradiction_kind="xss",
        )
    control_body, control_ev = control
    control_reflects = marker in control_body

    # Anchor contamination: if a payload's raw markup already appears when we
    # sent only the bare marker (no markup, nothing to reflect as a tag), then
    # that markup is a pre-existing page value and cannot discriminate un-escaped
    # reflection. Refuse to guess — INCONCLUSIVE, never a manufactured verdict.
    for _label, value in payloads.items():
        if value in control_body:
            return ValidationJudgment(
                hypothesis_id=hypothesis.id,
                experiment_id=control_experiment_id,
                status="INCONCLUSIVE",
                reason=(
                    "the control response already contains the raw payload markup "
                    f"'{value}' without any markup being injected — the reflection "
                    "anchor is contaminated, so surviving markup under a payload "
                    "cannot be attributed to un-escaped reflection"
                ),
                contradiction_kind="xss",
            )

    evidence_ids: list[str] = [control_ev]
    any_payload_readable = False

    for label, payload_id in payload_experiment_ids:
        probe = _probe_body(graph, payload_id)
        if probe is None:
            continue
        any_payload_readable = True
        body, payload_ev = probe

        value = payloads.get(label, "")
        breakout = bool(value) and (value in body)
        if breakout and control_reflects:
            evidence_ids.append(payload_ev)
            reason = (
                f"the '{label}' payload on '{expectation.param}' "
                f"({expectation.method} {expectation.path}) was reflected "
                f"VERBATIM as raw markup ('{value}') — the '<'/'>' survived output "
                "encoding un-escaped and carry our marker, and the control probe "
                f"proved the app reflects the bare marker '{marker}' — a real "
                "reflected XSS (an HTML-escaped value could never match the raw "
                "payload)"
            )
            return ValidationJudgment(
                hypothesis_id=hypothesis.id,
                experiment_id=payload_id,
                status="VALIDATED",
                reason=reason,
                contradiction_kind="xss",
                expected=False,   # boundary: the param MUST NOT reflect active markup
                observed=True,    # it did
                evidence_ids=tuple(dict.fromkeys(evidence_ids)),
            )

    if not any_payload_readable:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=control_experiment_id,
            status="INCONCLUSIVE",
            reason="no readable reflected-XSS payload probe for this hypothesis",
            contradiction_kind="xss",
        )

    return ValidationJudgment(
        hypothesis_id=hypothesis.id,
        experiment_id=control_experiment_id,
        status="DISPROVED",
        reason=(
            f"no payload made '{expectation.param}' "
            f"({expectation.method} {expectation.path}) reflect raw active markup: "
            "the parameter is HTML-escaped, stripped, or dropped, never reflected "
            "as executable markup — no reflected XSS (only blind/DOM-only XSS "
            "could remain, which this differential intentionally does not claim)"
        ),
        contradiction_kind="xss",
        expected=False,
        observed=False,
        evidence_ids=tuple(dict.fromkeys(evidence_ids)),
    )
