"""
PURE deterministic judge for the CORS class.

The analogue of :func:`judge_open_redirect`, reasoning over a **two-probe origin
differential** rather than a host one. Given a hypothesis, the id of a *payload*
probe (a request carrying an ``Origin`` header naming a random, unroutable nonce
origin) and the id of a *control* anchor probe (the SAME request with NO
``Origin`` header), it recovers the operator-declared surface and the seeded
nonce origin, reads the observed ``Access-Control-Allow-Origin`` (ACAO) and
``Access-Control-Allow-Credentials`` (ACAC) of each probe, and decides:

  VALIDATED     the payload response reflects the attacker origin — either the
                exact unforgeable nonce origin OR ``*`` — in ACAO, AND sets ACAC
                ``true``, AND the reflection is origin-driven (the no-Origin
                control anchor did not already carry that same ACAO value). A
                victim's browser would honour a credentialed cross-origin read
                from the attacker's site: a real, exploitable CORS
                misconfiguration;
  DISPROVED     the payload does not reflect our origin, OR reflects it WITHOUT
                credentials (a browser cannot read a credentialed response, so it
                is not exploitable — a lower-severity note), OR the same ACAO is
                present even on the no-Origin control (a static header, not
                origin-driven — also the post-fix state once the shield strips
                ACAO/ACAC);
  INCONCLUSIVE  the payload probe evidence is missing/unreadable, or the surface
                metadata (seeded nonce origin) is missing.

Three things make this sound. First, a reflected origin ALONE is never the
verdict — only reflection PLUS credentials is, because only a credentialed
response leaks data a cross-site attacker could not already fetch server-side.
Second, the nonce origin is random and appears ONLY in the payload ``Origin``
header, so an ACAO equal to it cannot be coincidental or a static config — it can
only be a reflection of our input. Third, the control anchor (no Origin)
establishes whether the ACAO is origin-driven, so a static ``*``/allowlist that
shows up regardless is not mistaken for reflection. The judge has no target
knowledge, performs no scoring, and never mutates the graph.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..graph import SecurityGraph
from ..models import Hypothesis, ValidationJudgment
@dataclass(frozen=True)
class CorsExpectation:
    """The declared cross-origin surface + seeded nonce origin for one identity."""

    method: str
    path: str
    endpoint_url: str
    nonce_host: str
    nonce_origin: str
    severity: str


def cors_expectation(
    graph: SecurityGraph,
    *,
    resource_id: str,
    aspect: str,
) -> CorsExpectation | None:
    """
    Recover the declared CORS surface for one hypothesis identity.

    ``aspect`` is the identity action (``"{method}:{path}"``); it keys onto the
    ``requires_safe_cors`` relationship the seeder emitted. Returns None if no
    matching edge exists, or the seeded nonce origin is missing (without it the
    judge cannot recognise a reflection, so the verdict must be INCONCLUSIVE).
    """
    target = f"cors:{aspect}"
    for relationship in graph.relationships:
        if (
            relationship.source == resource_id
            and relationship.relation == "requires_safe_cors"
            and relationship.target == target
        ):
            meta = dict(relationship.metadata)
            origin = meta.get("nonce_origin", "")
            if not origin:
                return None
            return CorsExpectation(
                method=meta.get("method", "GET"),
                path=meta.get("path", ""),
                endpoint_url=meta.get("endpoint_url", ""),
                nonce_host=meta.get("nonce_host", "").lower(),
                nonce_origin=origin.lower(),
                severity=meta.get("severity", "MEDIUM"),
            )
    return None
def _probe_evidence(graph: SecurityGraph, experiment):
    """The single HTTP probe evidence backing this experiment, or None.

    Mirrors the posture judge: an evidence qualifies only if it is a live HTTP
    fact (``mode == "http"``) carrying a ``response_headers`` dict. If zero or
    more than one qualifies, the probe is unreadable and we return None so the
    caller yields INCONCLUSIVE rather than guessing.
    """
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
            and isinstance(data.get("response_headers"), dict)
        ):
            candidates.append(evidence)
    if len(candidates) != 1:
        return None
    return candidates[0]


def _header(response_headers, name: str) -> str:
    """Case-insensitively read one response header value, or '' if absent."""
    wanted = name.lower()
    if isinstance(response_headers, dict):
        items = response_headers.items()
    else:
        items = response_headers or ()
    for key, value in items:
        if str(key).lower() == wanted:
            return str(value)
    return ""


def cors_response_headers(graph: SecurityGraph, experiment_id: str | None):
    """(acao, acac) for one probe, or None if its evidence is unreadable."""
    if experiment_id is None:
        return None
    evidence = _probe_evidence(graph, graph.experiments.get(experiment_id))
    if evidence is None:
        return None
    headers = evidence.data.get("response_headers")
    acao = _header(headers, "Access-Control-Allow-Origin")
    acac = _header(headers, "Access-Control-Allow-Credentials")
    return acao, acac
def judge_cors(
    graph: SecurityGraph,
    *,
    hypothesis: Hypothesis,
    control_experiment_id: str,
    payload_experiment_id: str,
) -> ValidationJudgment:
    """Decide whether the two-probe origin differential proves a CORS misconfig."""

    identity = hypothesis.identity
    if identity is None or not (identity.resource_id and identity.action):
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=payload_experiment_id,
            status="INCONCLUSIVE",
            reason="hypothesis lacks a resource/aspect identity",
            contradiction_kind="cors_misconfig",
        )

    expectation = cors_expectation(
        graph,
        resource_id=identity.resource_id,
        aspect=identity.action,
    )
    if expectation is None or not expectation.nonce_origin:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=payload_experiment_id,
            status="INCONCLUSIVE",
            reason=(
                "no declared CORS surface (or seeded nonce origin) for this "
                "hypothesis"
            ),
            contradiction_kind="cors_misconfig",
        )

    payload = cors_response_headers(graph, payload_experiment_id)
    if payload is None:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=payload_experiment_id,
            status="INCONCLUSIVE",
            reason="the origin-payload probe evidence is missing or unreadable",
            contradiction_kind="cors_misconfig",
        )
    payload_acao, payload_acac = payload

    # The control anchor may be absent (None) — treat its ACAO as empty. A
    # missing control cannot establish origin-drivenness on its own, but an exact
    # nonce reflection is unforgeable regardless (see below).
    control = cors_response_headers(graph, control_experiment_id)
    control_acao = control[0] if control is not None else ""
    nonce_origin = expectation.nonce_origin
    p_acao = (payload_acao or "").strip()
    c_acao = (control_acao or "").strip()

    reflects_nonce = p_acao.lower() == nonce_origin
    is_wildcard = p_acao == "*"
    credentials = (payload_acac or "").strip().lower() == "true"
    # Origin-driven iff the payload's ACAO is NOT the same value the no-Origin
    # control already carried. An exact nonce reflection is origin-driven by
    # construction (the server cannot statically emit our random nonce), so this
    # differential only really matters for the wildcard case.
    origin_driven = c_acao.lower() != p_acao.lower()
    reflected = reflects_nonce or is_wildcard

    payload_ev = _probe_evidence(graph, graph.experiments.get(payload_experiment_id))
    control_ev = _probe_evidence(graph, graph.experiments.get(control_experiment_id))
    evidence_ids = tuple(ev.id for ev in (payload_ev, control_ev) if ev is not None)

    reflected_desc = (
        f"the unforgeable nonce origin '{nonce_origin}'"
        if reflects_nonce
        else "the wildcard '*'"
    )

    if reflected and credentials and origin_driven:
        reason = (
            f"the origin-payload probe on {expectation.method} {expectation.path} "
            f"reflected {reflected_desc} in Access-Control-Allow-Origin and set "
            "Access-Control-Allow-Credentials: true, while the no-Origin control "
            "anchor proved the reflection is origin-driven (not a static header) "
            "— a victim's browser would honour a credentialed cross-origin read: "
            "a real CORS misconfiguration"
        )
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=payload_experiment_id,
            status="VALIDATED",
            reason=reason,
            contradiction_kind="cors_misconfig",
            expected=False,   # boundary: MUST NOT trust an arbitrary origin
            observed=True,    # it did
            evidence_ids=evidence_ids,
        )

    if reflected and not credentials:
        reason = (
            f"the origin-payload probe reflected {reflected_desc} in "
            "Access-Control-Allow-Origin but did NOT allow credentials — a browser "
            "cannot read a credentialed cross-origin response, so this is not an "
            "exploitable data leak (no finding)"
        )
    elif reflected and credentials and not origin_driven:
        reason = (
            "the Access-Control-Allow-Origin value appears even on the no-Origin "
            "control anchor — it is a STATIC header, not driven by our attacker "
            "Origin (also the post-fix state once the shield strips ACAO/ACAC): no "
            "origin-reflecting misconfiguration"
        )
    else:
        reason = (
            f"the origin-payload probe on {expectation.method} {expectation.path} "
            "did not reflect our attacker Origin in Access-Control-Allow-Origin "
            f"(observed ACAO '{p_acao or 'absent'}'): the endpoint does not trust "
            "an arbitrary cross-origin caller — no CORS misconfiguration"
        )

    return ValidationJudgment(
        hypothesis_id=hypothesis.id,
        experiment_id=payload_experiment_id,
        status="DISPROVED",
        reason=reason,
        contradiction_kind="cors_misconfig",
        expected=False,
        observed=False,
        evidence_ids=evidence_ids,
    )




