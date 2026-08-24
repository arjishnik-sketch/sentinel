"""
PURE deterministic judge for the path-traversal / LFI class.

The analogue of :func:`judge_reflected_xss`, but it reasons over an **OS-canary
differential** rather than a reflection one. Given a hypothesis, the id of a
*control* probe (a benign, traversal-free, non-OS filename) and the ids of a
*ladder* of payload probes (directory-escape shapes aimed at cross-OS canary
files — ``../../../../etc/passwd``, ``..\\..\\..\\windows\\win.ini``, absolute
paths, null-byte truncation), it recovers the operator-declared surface, reads
the observed response-body text of each probe, and decides:

  VALIDATED     some payload response contains an OS-file INVARIANT
                (``root:x:0:0:`` for ``/etc/passwd``, a ``[fonts]``/
                ``[extensions]`` section for ``win.ini``) that is ABSENT from the
                control — a system file provably leaked through directory escape
                (a real path traversal / LFI);
  DISPROVED     no payload leaked any OS invariant — the parameter is
                canonicalised, confined to a safe root, or simply not a file sink
                (also the post-fix state once the request-guard blocks the escape
                shapes);
  INCONCLUSIVE  the control probe evidence is missing/unreadable, or the control
                response ALREADY carries an OS invariant (its anchor is
                contaminated — the signature is present independent of any escape,
                so a leak under a payload cannot be attributed to traversal), or
                no payload probe was readable, or the surface metadata is missing.

Three things make this sound. First, a status code alone is never the verdict —
only the presence of a system-file invariant in the body is. Second, that
invariant (``root:x:0:0:`` / a win.ini section) is content a normal application
response could never contain by coincidence, so its appearance is attributable to
a file read. Third, the control anchors the differential: an invariant that
appears ONLY under an escape payload — never in the benign, traversal-free
baseline — is attributable to directory escape and not to an error page that
merely mentions "root". The judge has no target knowledge, performs no scoring,
and never mutates the graph.

Scope (stated honestly): this proves the load-bearing effect of path traversal /
LFI — an attacker-controlled parameter reading a file OUTSIDE the intended
directory, evidenced by a known OS canary. Files without a stable invariant
signature (arbitrary application source) cannot be proven by canary alone, so the
class is deliberately CONSERVATIVE: only a known-canary leak is CONFIRMED; other
reads never manufacture a verdict.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..graph import SecurityGraph
from ..models import Hypothesis, ValidationJudgment
from .traversal_policy import leaked_canary

@dataclass(frozen=True)
class TraversalExpectation:
    """The declared path-traversal surface + control filename for one identity."""

    method: str
    path: str
    endpoint_url: str
    param: str
    location: str
    control_value: str
    severity: str


def traversal_expectation(
    graph: SecurityGraph,
    *,
    resource_id: str,
    aspect: str,
) -> TraversalExpectation | None:
    """Recover the declared path-traversal surface for one hypothesis identity.

    `aspect` is the identity action; it keys onto the
    ``requires_no_path_traversal`` relationship the seeder emitted. Returns None
    if no matching edge exists (or the seeded control filename is missing).
    """
    target = f"traversal:{aspect}"
    for relationship in graph.relationships:
        if (
            relationship.source == resource_id
            and relationship.relation == "requires_no_path_traversal"
            and relationship.target == target
        ):
            meta = dict(relationship.metadata)
            control = meta.get("control", "")
            if not control:
                return None
            return TraversalExpectation(
                method=meta.get("method", "GET"),
                path=meta.get("path", ""),
                endpoint_url=meta.get("endpoint_url", ""),
                param=meta.get("param", ""),
                location=meta.get("location", "query"),
                control_value=control,
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

def judge_path_traversal(
    graph: SecurityGraph,
    *,
    hypothesis: Hypothesis,
    control_experiment_id: str,
    payload_experiment_ids: tuple[tuple[str, str], ...],
) -> ValidationJudgment:
    """Decide whether the OS-canary differential proves a path traversal / LFI.

    ``payload_experiment_ids`` is a tuple of ``(label, experiment_id)`` pairs;
    each payload probe carried a different directory-escape shape aimed at a
    cross-OS canary file.
    """

    identity = hypothesis.identity
    if identity is None or not (identity.resource_id and identity.action):
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=control_experiment_id,
            status="INCONCLUSIVE",
            reason="hypothesis lacks a resource/aspect identity",
            contradiction_kind="path_traversal",
        )

    expectation = traversal_expectation(
        graph,
        resource_id=identity.resource_id,
        aspect=identity.action,
    )
    if expectation is None or not expectation.param:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=control_experiment_id,
            status="INCONCLUSIVE",
            reason="no declared path-traversal surface (or seeded control) for this hypothesis",
            contradiction_kind="path_traversal",
        )

    control = _probe_body(graph, control_experiment_id)
    if control is None:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=control_experiment_id,
            status="INCONCLUSIVE",
            reason="the control probe evidence is missing or unreadable",
            contradiction_kind="path_traversal",
        )
    control_body, control_ev = control

    # Anchor contamination: if the benign, traversal-free control response ALREADY
    # carries an OS-file invariant, that signature is present independent of any
    # escape (e.g. an app that echoes system content on every response), so a leak
    # under a payload cannot be attributed to directory traversal. Refuse to guess
    # — INCONCLUSIVE, never a manufactured verdict.
    control_leak = leaked_canary(control_body)
    if control_leak is not None:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=control_experiment_id,
            status="INCONCLUSIVE",
            reason=(
                f"the benign control response already carries the '{control_leak}' "
                "OS-file invariant without any directory escape — the canary anchor "
                "is contaminated, so a leak under a payload cannot be attributed to "
                "path traversal"
            ),
            contradiction_kind="path_traversal",
        )

    evidence_ids: list[str] = [control_ev]
    any_payload_readable = False

    for label, payload_id in payload_experiment_ids:
        probe = _probe_body(graph, payload_id)
        if probe is None:
            continue
        any_payload_readable = True
        body, payload_ev = probe

        leak = leaked_canary(body)
        if leak is not None:
            evidence_ids.append(payload_ev)
            reason = (
                f"the '{label}' payload on '{expectation.param}' "
                f"({expectation.method} {expectation.path}) leaked the '{leak}' "
                "OS-file invariant into the response body — a system file was read "
                "through directory escape while the benign control (no traversal) "
                "carried no such invariant: a real path traversal / LFI (a normal "
                "application response could never contain this signature)"
            )
            return ValidationJudgment(
                hypothesis_id=hypothesis.id,
                experiment_id=payload_id,
                status="VALIDATED",
                reason=reason,
                contradiction_kind="path_traversal",
                expected=False,  # boundary: the param MUST NOT read files outside root
                observed=True,   # it did
                evidence_ids=tuple(dict.fromkeys(evidence_ids)),
            )

    if not any_payload_readable:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=control_experiment_id,
            status="INCONCLUSIVE",
            reason="no readable path-traversal payload probe for this hypothesis",
            contradiction_kind="path_traversal",
        )

    return ValidationJudgment(
        hypothesis_id=hypothesis.id,
        experiment_id=control_experiment_id,
        status="DISPROVED",
        reason=(
            f"no payload made '{expectation.param}' "
            f"({expectation.method} {expectation.path}) leak an OS-file invariant: "
            "the parameter is canonicalised, confined to a safe root, or is not a "
            "file sink — no path traversal (a read without a known canary is never "
            "claimed by this differential)"
        ),
        contradiction_kind="path_traversal",
        expected=False,
        observed=False,
        evidence_ids=tuple(dict.fromkeys(evidence_ids)),
    )
