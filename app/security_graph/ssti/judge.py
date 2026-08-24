"""
PURE deterministic judge for the SSTI (server-side template injection) class.

The analogue of :func:`judge_injection`, but it reasons over an
**arithmetic-evaluation differential** rather than a boolean one. Given a
hypothesis, the id of a *control* probe (the literal expression ``a*b`` with no
template delimiters) and the ids of one or more *payload* probes (that same
``a*b`` wrapped in template delimiters), it recovers the operator-declared
surface and the seeded operands the seeder wrote into the graph, reads the
observed response-body text of each probe, and decides:

  VALIDATED     some payload response contains the *computed product* ``a*b``
                while the literal expression ``a*b`` is gone, AND the control
                proved the app merely reflects the literal (the literal is
                present, the product is not) — so the product can only have been
                produced by the backend *evaluating* the template (a real SSTI);
  DISPROVED     no payload yielded the product with the literal gone — the
                parameter is reflected verbatim or dropped, never evaluated (also
                the post-fix state once the request-guard blocks the delimiters);
  INCONCLUSIVE  the control probe evidence is missing/unreadable, or the control
                already contains the product (its anchor is contaminated — the
                product appears with no template evaluation at all, so nothing
                can discriminate), or no payload probe was readable, or the
                surface metadata is missing.

Three things make this sound. First, a status code alone is never the verdict —
only the presence of the *computed* value in the body is. Second, a payload
reflected verbatim still contains the literal ``a*b`` inside its delimiters, so
"literal gone AND product present" cannot be produced by mere reflection — only
by evaluation. Third, the control anchors the differential: it proves the app
reflects the literal and that the product is NOT already on the page, so a
product appearing only under a template delimiter is attributable to evaluation
and not to coincidence. The judge has no target knowledge, performs no scoring,
and never mutates the graph.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..graph import SecurityGraph
from ..models import Hypothesis, ValidationJudgment


@dataclass(frozen=True)
class SSTIExpectation:
    """The declared SSTI surface + seeded operands for one hypothesis identity."""

    method: str
    path: str
    endpoint_url: str
    param: str
    location: str
    literal_expr: str
    product: str
    severity: str


def ssti_expectation(
    graph: SecurityGraph,
    *,
    resource_id: str,
    aspect: str,
) -> SSTIExpectation | None:
    """
    Recover the declared SSTI surface for one hypothesis identity.

    `aspect` is the identity action; it keys onto the
    ``requires_no_template_injection`` relationship the seeder emitted. Returns
    None if no matching edge exists (or the seeded operands are missing).
    """
    target = f"template_injection:{aspect}"
    for relationship in graph.relationships:
        if (
            relationship.source == resource_id
            and relationship.relation == "requires_no_template_injection"
            and relationship.target == target
        ):
            meta = dict(relationship.metadata)
            literal_expr = meta.get("literal_expr", "")
            product = meta.get("product", "")
            if not literal_expr or not product:
                return None
            return SSTIExpectation(
                method=meta.get("method", "GET"),
                path=meta.get("path", ""),
                endpoint_url=meta.get("endpoint_url", ""),
                param=meta.get("param", ""),
                location=meta.get("location", "query"),
                literal_expr=literal_expr,
                product=product,
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


def judge_template_injection(
    graph: SecurityGraph,
    *,
    hypothesis: Hypothesis,
    control_experiment_id: str,
    payload_experiment_ids: tuple[tuple[str, str], ...],
) -> ValidationJudgment:
    """Decide whether the arithmetic-evaluation differential proves an SSTI.

    ``payload_experiment_ids`` is a tuple of ``(label, experiment_id)`` pairs;
    each payload probe wrapped the SAME literal expression in a different
    template delimiter.
    """

    identity = hypothesis.identity
    if identity is None or not (identity.resource_id and identity.action):
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=control_experiment_id,
            status="INCONCLUSIVE",
            reason="hypothesis lacks a resource/aspect identity",
            contradiction_kind="template_injection",
        )

    expectation = ssti_expectation(
        graph,
        resource_id=identity.resource_id,
        aspect=identity.action,
    )
    if expectation is None or not expectation.param:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=control_experiment_id,
            status="INCONCLUSIVE",
            reason="no declared SSTI surface (or seeded operands) for this hypothesis",
            contradiction_kind="template_injection",
        )

    literal = expectation.literal_expr
    product = expectation.product

    control = _probe_body(graph, control_experiment_id)
    if control is None:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=control_experiment_id,
            status="INCONCLUSIVE",
            reason="the control probe evidence is missing or unreadable",
            contradiction_kind="template_injection",
        )
    control_body, control_ev = control
    control_reflects = literal in control_body
    control_has_product = product in control_body

    # Anchor contamination: if the computed product already appears when we send
    # only the literal (no delimiters, nothing to evaluate), then the product is
    # a coincidental page value and cannot discriminate evaluation. Refuse to
    # guess — INCONCLUSIVE, never a manufactured verdict.
    if control_has_product:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=control_experiment_id,
            status="INCONCLUSIVE",
            reason=(
                f"the control response already contains {product} without any "
                "template delimiters — the arithmetic anchor is contaminated, so "
                "a product under a delimiter cannot be attributed to evaluation"
            ),
            contradiction_kind="template_injection",
        )

    evidence_ids: list[str] = [control_ev]
    any_payload_readable = False

    for label, payload_id in payload_experiment_ids:
        probe = _probe_body(graph, payload_id)
        if probe is None:
            continue
        any_payload_readable = True
        body, payload_ev = probe

        evaluated = (product in body) and (literal not in body)
        if evaluated and control_reflects:
            evidence_ids.append(payload_ev)
            reason = (
                f"the '{label}' template payload on '{expectation.param}' "
                f"({expectation.method} {expectation.path}) rendered the computed "
                f"product {product} while the literal expression '{literal}' "
                "vanished, and the control probe proved the app merely reflects "
                f"'{literal}' (product absent) — the backend evaluated the "
                "template (a reflected value cannot compute arithmetic)"
            )
            return ValidationJudgment(
                hypothesis_id=hypothesis.id,
                experiment_id=payload_id,
                status="VALIDATED",
                reason=reason,
                contradiction_kind="template_injection",
                expected=False,   # boundary: the param MUST NOT be evaluated
                observed=True,    # it was
                evidence_ids=tuple(dict.fromkeys(evidence_ids)),
            )

    if not any_payload_readable:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=control_experiment_id,
            status="INCONCLUSIVE",
            reason="no readable template payload probe for this hypothesis",
            contradiction_kind="template_injection",
        )

    return ValidationJudgment(
        hypothesis_id=hypothesis.id,
        experiment_id=control_experiment_id,
        status="DISPROVED",
        reason=(
            f"no template payload made '{expectation.param}' "
            f"({expectation.method} {expectation.path}) compute {product}: the "
            "parameter is reflected verbatim or dropped, never evaluated by a "
            "template engine — no SSTI (only blind, non-reflected SSTI could "
            "remain, which this differential intentionally does not claim)"
        ),
        contradiction_kind="template_injection",
        expected=False,
        observed=False,
        evidence_ids=tuple(dict.fromkeys(evidence_ids)),
    )
