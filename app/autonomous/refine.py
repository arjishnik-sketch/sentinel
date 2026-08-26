"""FAILURE-CAUSE analysis → mutated re-probes: the "propose again, differently"
half of the adaptive loop.

When a pure judge returns a NON-terminal verdict (INCONCLUSIVE — could not build
or anchor a differential; ERROR — the judge faulted) the first probe shape was
wrong, not the target. This module diagnoses the likely cause from the verdict's
own detail + the hypothesis shape and emits MUTATED hypotheses (same technique,
same in-scope URL, a different probe shape) to try next.

CONTRACT — this is squarely the "propose" half of "propose / dispose". A retry
NEVER manufactures a verdict: it only re-poses a differently-shaped question, and
the SAME pure judge disposes each variant independently downstream. Terminal
verdicts (CONFIRMED / DISPROVED / LEAD) are never retried — a measured result,
positive or negative, is the judge's to keep.

The deterministic rules below are the FLOOR (LLM entirely off → fully
deterministic, offline-testable). An optional ``propose_extra`` seam lets a live
run fold in LLM-proposed variants on top of the floor; those variants are still
just proposals routed through the same judge.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from urllib.parse import urlsplit

from .hypotheses import Hypothesis, _AUTH_URL_WORDS, _LOGIN_SUCCESS_STATUSES

# Only these verdicts admit a retry: the differential was not honestly measured.
# CONFIRMED / DISPROVED / LEAD are terminal and pass through untouched.
RETRYABLE = ("INCONCLUSIVE", "ERROR")

# Body locations we toggle between for a POST injection whose shape we guessed.
_BODY_LOCS = ("body_json", "body_form")


@dataclass(frozen=True)
class Retry:
    """One mutated re-probe proposal: the shape to try + why."""
    hypothesis: Hypothesis
    cause: str        # diagnosed failure cause (human label)
    mutation: str     # the axis that was changed


def _is_login_shaped(url: str) -> bool:
    path = urlsplit(url if "://" in (url or "") else f"http://{url or ''}").path.lower()
    return any(w in path for w in _AUTH_URL_WORDS)


def _sql_body_variants(hyp) -> list:
    """Body-shape mutations for a POST SQL-injection whose location we guessed.

    A login endpoint is either a JSON API (``body_json``) or a classic form POST
    (``body_form``); recon cannot always tell which, and the wrong guess yields an
    unanchored INCONCLUSIVE. So: toggle to the other body location, and — for an
    auth-shaped URL that carries no success-status anchor yet — attach the login's
    real legitimate baseline (401/403/200) so the pure judge's anchor gate has
    something to measure against. Ordered, deterministic; de-duped by key upstream.
    """
    loc = (hyp.location or "").lower()
    if hyp.technique != "sql_injection" or (hyp.method or "").upper() != "POST":
        return []
    if loc not in ("body", "body_form", "body_json"):
        return []

    other = _BODY_LOCS[1] if loc in ("body_json",) else _BODY_LOCS[0]
    login = _is_login_shaped(hyp.url)
    needs_anchor = login and not getattr(hyp, "success_statuses", None)
    anchor = _LOGIN_SUCCESS_STATUSES if needs_anchor else getattr(hyp, "success_statuses", None)

    out = []
    # 1) toggle the body shape (carry any anchor we already had).
    out.append((replace(hyp, location=other, source="retry",
                         rationale=f"retry: body shape {loc}→{other}"),
                "wrong body shape (JSON vs form)", f"location {loc}→{other}"))
    # 2/3) if a login lacks an anchor, retry BOTH shapes with the login baseline.
    if needs_anchor:
        out.append((replace(hyp, success_statuses=anchor, source="retry",
                            rationale="retry: attach login success anchor"),
                    "no anchor on login baseline (non-2xx)", "success_statuses"))
        out.append((replace(hyp, location=other, success_statuses=anchor, source="retry",
                            rationale=f"retry: {loc}→{other} + login anchor"),
                    "no anchor on login baseline (non-2xx)", f"location {loc}→{other}+anchor"))
    return out


def _param_backfill_variants(hyp, surface) -> list:
    """When a provable hypothesis reached the judge with no parameter to probe,
    re-pose it against each parameter the surface actually observed."""
    if not getattr(hyp, "provable", False) or (hyp.param and str(hyp.param).strip()):
        return []
    out = []
    for name in getattr(surface, "params", ()) or ():
        if not isinstance(name, str) or not name.strip():
            continue
        out.append((replace(hyp, param=name, source="retry",
                            rationale=f"retry: backfill param '{name}'"),
                    "no parameter to probe", f"param=∅→{name}"))
    return out


def diagnose(verdict, surface, *, tried=(), propose_extra=None):
    """Diagnose ONE non-terminal verdict → an ordered, de-duped tuple of ``Retry``.

    ``tried`` is the set of hypothesis SHAPES already adjudicated (any round) — we
    never re-issue an identical probe shape. Shape (not ``key``) is the dedup unit
    so that anchored and un-anchored variants of the same location are both
    reachable. ``propose_extra(verdict, surface)`` is an optional live seam (e.g.
    an LLM proposer) whose extra hypotheses are appended AFTER the deterministic
    floor and filtered by the same dedup/scope rules. Returns ``()`` for a terminal
    verdict — nothing to retry.
    """
    status = getattr(verdict, "status", "")
    if status not in RETRYABLE:
        return ()
    hyp = verdict.hypothesis
    detail = (getattr(verdict, "detail", "") or "").lower()

    candidates = []
    # param backfill fires only when the judge explicitly had no parameter.
    if "no parameter" in detail or not (hyp.param and str(hyp.param).strip()):
        candidates += _param_backfill_variants(hyp, surface)
    candidates += _sql_body_variants(hyp)

    if propose_extra is not None:
        try:
            for h in propose_extra(verdict, surface) or ():
                if isinstance(h, Hypothesis):
                    candidates.append((h, "llm-proposed refinement", "llm"))
        except Exception:
            pass  # a flaky proposer must never break the loop

    host = surface.host
    seen = set(tried or ())
    out = []
    for h, cause, mutation in candidates:
        # scope: a retry can never wander off the observed host.
        netloc = urlsplit(h.url if "://" in (h.url or "") else f"http://{h.url or ''}").netloc.lower()
        if host and netloc and netloc != host:
            continue
        if h.shape in seen:
            continue
        seen.add(h.shape)
        out.append(Retry(hypothesis=h, cause=cause, mutation=mutation))
    return tuple(out)
