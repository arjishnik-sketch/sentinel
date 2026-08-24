"""
PURE deterministic judge for the open-redirect class.

The analogue of :func:`judge_template_injection`, but it reasons over a
**two-probe host differential** rather than an arithmetic one. Given a hypothesis,
the id of an *off-origin payload* probe (the redirect parameter set to a URL on a
random, unroutable nonce host) and the id of a same-origin *control* anchor probe
(the parameter set to the target's own origin), it recovers the operator-declared
surface and the seeded nonce host, reads the observed ``Location`` header of each
probe, and decides:

  VALIDATED     the payload response is a redirect (3xx) whose ``Location`` host
                equals the seeded nonce host — a host that could ONLY have come
                from our parameter value — AND the control anchor proves the
                endpoint legitimately redirects on-origin (the differential's
                baseline). The redirect destination is provably attacker-
                controlled: a real open redirect;
  DISPROVED     the payload did not redirect to the nonce host — the parameter is
                ignored, sanitized, or forced on-origin (also the post-fix state
                once the url-allowlist request-guard blocks the off-origin value);
  INCONCLUSIVE  the payload probe evidence is missing/unreadable, or the surface
                metadata is missing, or the payload DID redirect off-origin to the
                nonce host but the same-origin control anchor did NOT reproduce an
                on-origin redirect (the differential's baseline is unestablished,
                so the observation is refused rather than guessed).

Three things make this sound. First, a status code alone is never the verdict —
only a ``Location`` host built from our unique nonce is. Second, the nonce is
random and appears ONLY in the payload parameter value, so a ``Location`` host
equal to it cannot be coincidental or forged by the server's own configuration —
it can only be a reflection of our input into the redirect target. Third, the
control anchor establishes that the endpoint is a genuine on-origin redirector, so
the payload's off-origin ``Location`` is a provable *deviation* into attacker
territory. The judge has no target knowledge, performs no scoring, and never
mutates the graph.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from ..graph import SecurityGraph
from ..models import Hypothesis, ValidationJudgment


@dataclass(frozen=True)
class OpenRedirectExpectation:
    """The declared redirect surface + seeded probe hosts for one identity."""

    method: str
    path: str
    endpoint_url: str
    param: str
    location: str
    nonce_host: str
    payload_url: str
    control_url: str
    target_host: str
    severity: str


def open_redirect_expectation(
    graph: SecurityGraph,
    *,
    resource_id: str,
    aspect: str,
) -> OpenRedirectExpectation | None:
    """
    Recover the declared redirect surface for one hypothesis identity.

    `aspect` is the identity action; it keys onto the
    ``requires_no_open_redirect`` relationship the seeder emitted. Returns None
    if no matching edge exists (or the seeded hosts are missing).
    """
    target = f"open_redirect:{aspect}"
    for relationship in graph.relationships:
        if (
            relationship.source == resource_id
            and relationship.relation == "requires_no_open_redirect"
            and relationship.target == target
        ):
            meta = dict(relationship.metadata)
            host = meta.get("nonce_host", "")
            payload = meta.get("payload_url", "")
            control = meta.get("control_url", "")
            if not host or not payload or not control:
                return None
            endpoint_url = meta.get("endpoint_url", "")
            return OpenRedirectExpectation(
                method=meta.get("method", "GET"),
                path=meta.get("path", ""),
                endpoint_url=endpoint_url,
                param=meta.get("param", ""),
                location=meta.get("location", "query"),
                nonce_host=host.lower(),
                payload_url=payload,
                control_url=control,
                target_host=(urlsplit(endpoint_url).hostname or "").lower(),
                severity=meta.get("severity", "MEDIUM"),
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
            and "response_headers" in data
        ):
            candidates.append(evidence)
    if len(candidates) != 1:
        return None
    return candidates[0]


def _location_header(response_headers) -> str:
    """Case-insensitively read the ``Location`` header, or '' if absent."""
    if isinstance(response_headers, dict):
        items = response_headers.items()
    else:
        items = response_headers or ()
    for name, value in items:
        if str(name).lower() == "location":
            return str(value)
    return ""


def _redirect_host(graph: SecurityGraph, experiment_id: str | None):
    """
    (status_code, location, host) for a probe, or None if unreadable.

    ``host`` is the lowercased hostname the ``Location`` resolves to — empty
    string for a relative/on-origin ``Location`` (which carries no host).
    """
    if experiment_id is None:
        return None
    evidence = _probe_evidence(graph, graph.experiments.get(experiment_id))
    if evidence is None:
        return None
    data = evidence.data
    raw_code = data.get("status_code")
    try:
        code = int(raw_code) if raw_code is not None else None
    except (TypeError, ValueError):
        code = None
    location = _location_header(data.get("response_headers"))
    host = (urlsplit(location).hostname or "").lower() if location else ""
    return code, location, host


def _is_redirect(code: int | None) -> bool:
    return code is not None and 300 <= code < 400


def judge_open_redirect(
    graph: SecurityGraph,
    *,
    hypothesis: Hypothesis,
    control_experiment_id: str,
    payload_experiment_id: str,
) -> ValidationJudgment:
    """Decide whether the two-probe host differential proves an open redirect."""

    identity = hypothesis.identity
    if identity is None or not (identity.resource_id and identity.action):
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=payload_experiment_id,
            status="INCONCLUSIVE",
            reason="hypothesis lacks a resource/aspect identity",
            contradiction_kind="open_redirect",
        )

    expectation = open_redirect_expectation(
        graph,
        resource_id=identity.resource_id,
        aspect=identity.action,
    )
    if expectation is None or not expectation.param:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=payload_experiment_id,
            status="INCONCLUSIVE",
            reason=(
                "no declared open-redirect surface (or seeded nonce host) for "
                "this hypothesis"
            ),
            contradiction_kind="open_redirect",
        )

    nonce_host = expectation.nonce_host
    target_host = expectation.target_host

    payload = _redirect_host(graph, payload_experiment_id)
    if payload is None:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=payload_experiment_id,
            status="INCONCLUSIVE",
            reason="the off-origin payload probe evidence is missing or unreadable",
            contradiction_kind="open_redirect",
        )
    payload_code, _payload_loc, payload_host = payload

    control = _redirect_host(graph, control_experiment_id)
    control_ev = None
    control_on_origin = False
    if control is not None:
        control_code, _control_loc, control_host = control
        # On-origin: a relative Location (no host) or a Location whose host is the
        # target itself — the legitimate baseline a genuine redirector reproduces.
        control_on_origin = _is_redirect(control_code) and (
            control_host == "" or control_host == target_host
        )
        control_ev = _probe_evidence(graph, graph.experiments.get(control_experiment_id))

    payload_off_origin = _is_redirect(payload_code) and payload_host == nonce_host

    payload_ev = _probe_evidence(graph, graph.experiments.get(payload_experiment_id))
    evidence_ids = tuple(
        ev.id for ev in (payload_ev, control_ev) if ev is not None
    )

    if payload_off_origin and control_on_origin:
        reason = (
            f"the off-origin payload on '{expectation.param}' "
            f"({expectation.method} {expectation.path}) produced a {payload_code} "
            f"redirect whose Location host is the unforgeable nonce host "
            f"'{nonce_host}' — a host that could only have come from our parameter "
            "value — while the same-origin control anchor proved the endpoint "
            "legitimately redirects on-origin: the redirect destination is "
            "attacker-controlled (a real open redirect)"
        )
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=payload_experiment_id,
            status="VALIDATED",
            reason=reason,
            contradiction_kind="open_redirect",
            expected=False,   # boundary: the param MUST NOT redirect off-origin
            observed=True,    # it did
            evidence_ids=evidence_ids,
        )

    if payload_off_origin and not control_on_origin:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=payload_experiment_id,
            status="INCONCLUSIVE",
            reason=(
                f"the payload redirected off-origin to '{nonce_host}', but the "
                "same-origin control anchor did NOT reproduce an on-origin "
                "redirect — the differential's baseline is unestablished, so the "
                "observation is refused rather than claimed"
            ),
            contradiction_kind="open_redirect",
        )

    return ValidationJudgment(
        hypothesis_id=hypothesis.id,
        experiment_id=payload_experiment_id,
        status="DISPROVED",
        reason=(
            f"the off-origin payload on '{expectation.param}' "
            f"({expectation.method} {expectation.path}) did not redirect to the "
            f"nonce host '{nonce_host}' (observed status {payload_code}): the "
            "parameter is ignored, sanitized, or forced on-origin — no open "
            "redirect (also the post-fix state once the url-allowlist "
            "request-guard blocks the off-origin value)"
        ),
        contradiction_kind="open_redirect",
        expected=False,
        observed=False,
        evidence_ids=evidence_ids,
    )
