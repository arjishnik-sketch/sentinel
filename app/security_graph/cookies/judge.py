"""
PURE deterministic judge for the insecure-cookie class.

The analogue of :func:`judge_header_posture`. Given a hypothesis and the id of
a completed cookie probe, it selects the single probe evidence, reads the
operator-declared expectation the seeder wrote into the graph, parses the raw
``Set-Cookie`` header(s) the target actually returned, and compares the
observed cookie attributes against the expectation. It returns:

  VALIDATED     an observed cookie CONTRADICTS the declared posture — the weak
                cookie reproduces (finding-worthy);
  DISPROVED     the observed cookie(s) SATISFY the posture, OR the route issues
                no matching cookie at all — no finding;
  INCONCLUSIVE  the evidence is missing/ambiguous, or no posture is declared.

It has no target knowledge, performs no scoring, and never mutates the graph.
A single unambiguous comparison over the *observed* ``Set-Cookie`` decides the
verdict — the expectation is only ever asserted against a cookie the target
genuinely sets.
"""

from __future__ import annotations

from ..graph import SecurityGraph
from ..models import Hypothesis, ValidationJudgment
from .cookie_policy import CookieExpectation


def cookie_posture_expectation(
    graph: SecurityGraph,
    *,
    resource_id: str,
    aspect: str,
) -> CookieExpectation | None:
    """
    Recover the declared cookie expectation for one hypothesis identity.

    `aspect` is the identity action, ``"{name}:{check}:{token}"``; it keys
    directly onto the ``requires_cookie_posture`` relationship the seeder
    emitted. Returns None if no matching posture edge exists.
    """
    target = f"cookie:{aspect}"
    for relationship in graph.relationships:
        if (
            relationship.source == resource_id
            and relationship.relation == "requires_cookie_posture"
            and relationship.target == target
        ):
            meta = dict(relationship.metadata)
            return CookieExpectation(
                cookie_name=meta.get("cookie_name", ""),
                check=meta.get("check", ""),
                flag=(meta.get("flag") or None),
                value=(meta.get("value") or None),
                severity=meta.get("severity", "MEDIUM"),
            )
    return None


def _probe_evidence(graph: SecurityGraph, experiment):
    """The single HTTP cookie-probe evidence backing this experiment, or None."""
    candidates = []
    for evidence_id in experiment.evidence_ids:
        evidence = graph.evidence.get(evidence_id)
        if evidence is None:
            continue
        data = evidence.data
        if (
            isinstance(data, dict)
            and data.get("mode") == "http"
            and isinstance(data.get("set_cookie"), list)
        ):
            candidates.append(evidence)
    if len(candidates) != 1:
        return None
    return candidates[0]


def _parse_set_cookie(line: str):
    """
    Parse one raw ``Set-Cookie`` line into ``(name, flags, samesite)``.

    ``flags`` is a set of lowercase valueless attribute names (``httponly``,
    ``secure``); ``samesite`` is the SameSite value as sent (or None). No
    judgement is made here — this only tokenises the observed header.
    """
    segments = [seg.strip() for seg in str(line).split(";") if seg.strip()]
    if not segments:
        return "", set(), None
    name = segments[0].split("=", 1)[0].strip()
    flags: set[str] = set()
    samesite: str | None = None
    for seg in segments[1:]:
        if "=" in seg:
            key, val = seg.split("=", 1)
            if key.strip().lower() == "samesite":
                samesite = val.strip()
        else:
            flags.add(seg.strip().lower())
    return name, flags, samesite


def _matching_cookies(set_cookies, cookie_name: str):
    """Every parsed cookie matching the expectation's cookie_name (or all)."""
    wanted = (cookie_name or "").strip()
    parsed = [_parse_set_cookie(line) for line in set_cookies]
    if not wanted:
        return parsed
    return [item for item in parsed if item[0] == wanted]


def _is_compliant(expectation: CookieExpectation, matching) -> bool:
    """
    Deterministic cookie check: True iff the observed cookies satisfy policy.

    A route that issues no matching cookie is compliant by construction — we
    only ever flag a cookie the target genuinely sets (the honest differential).
    """
    if not matching:
        return True

    check = expectation.check
    if check == "must_have_flag":
        flag = (expectation.flag or "").lower()
        return all(flag in flags for _n, flags, _s in matching)
    if check == "must_not_have_flag":
        flag = (expectation.flag or "").lower()
        return all(flag not in flags for _n, flags, _s in matching)
    if check == "samesite_must_equal":
        want = (expectation.value or "").strip().lower()
        return all(
            samesite is not None and samesite.strip().lower() == want
            for _n, _f, samesite in matching
        )
    if check == "samesite_must_not_equal":
        want = (expectation.value or "").strip().lower()
        return all(
            samesite is None or samesite.strip().lower() != want
            for _n, _f, samesite in matching
        )
    # Unknown check — cannot decide.
    return True


def _reason(expectation: CookieExpectation, matching, compliant: bool) -> str:
    label = expectation.cookie_name or "any"
    verb = "satisfies" if compliant else "violates"
    if expectation.check in ("must_have_flag", "must_not_have_flag"):
        want = f"{expectation.check} {expectation.flag}"
    else:
        want = f"{expectation.check} {expectation.value}"
    if not matching:
        shown = "no matching Set-Cookie observed"
    else:
        parts = []
        for name, flags, samesite in matching:
            attrs = sorted(flags)
            if samesite is not None:
                attrs.append(f"samesite={samesite}")
            parts.append(f"{name}[{', '.join(attrs) or 'no-attrs'}]")
        shown = "; ".join(parts)
    return (
        f"observed cookie '{label}' ({shown}) {verb} declared posture ({want})"
    )


def judge_cookie_posture(
    graph: SecurityGraph,
    *,
    hypothesis: Hypothesis,
    experiment_id: str,
) -> ValidationJudgment:
    """Decide whether an observed cookie contradicts the declared posture."""

    experiment = graph.experiments.get(experiment_id)
    if experiment is None:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=experiment_id,
            status="INCONCLUSIVE",
            reason="no experiment found for cookie posture judgment",
            contradiction_kind="insecure_cookie",
        )

    identity = hypothesis.identity
    if identity is None or not (identity.resource_id and identity.action):
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=experiment_id,
            status="INCONCLUSIVE",
            reason="hypothesis lacks a resource/aspect identity",
            contradiction_kind="insecure_cookie",
        )

    expectation = cookie_posture_expectation(
        graph,
        resource_id=identity.resource_id,
        aspect=identity.action,
    )
    if expectation is None or not expectation.check:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=experiment_id,
            status="INCONCLUSIVE",
            reason="no declared cookie posture for this hypothesis",
            contradiction_kind="insecure_cookie",
        )

    evidence = _probe_evidence(graph, experiment)
    if evidence is None:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=experiment_id,
            status="INCONCLUSIVE",
            reason="expected exactly one HTTP cookie probe for this experiment",
            contradiction_kind="insecure_cookie",
        )

    matching = _matching_cookies(
        evidence.data["set_cookie"], expectation.cookie_name
    )
    compliant = _is_compliant(expectation, matching)

    # The hypothesis claims an insecure cookie. It is VALIDATED when an
    # observed cookie CONTRADICTS the required posture (a real weakness),
    # DISPROVED when the cookie satisfies it or is simply not set.
    status = "DISPROVED" if compliant else "VALIDATED"

    return ValidationJudgment(
        hypothesis_id=hypothesis.id,
        experiment_id=experiment_id,
        status=status,
        reason=_reason(expectation, matching, compliant),
        contradiction_kind="insecure_cookie",
        expected=True,          # posture required
        observed=compliant,     # posture actually satisfied?
        evidence_ids=(evidence.id,),
    )
