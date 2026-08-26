"""Exercise the CONCRETE IMPACT of a confirmed token forgery — dynamically.

Once the pure judge has CONFIRMED that a forged token is accepted where the
genuine session works and anonymous is denied, the forgery's real consequence is
whatever that forged privilege can now DO: reach an admin panel, and from it
perform a privileged action (delete a user, change a role, export data). Proving
the bypass is Sentinel's job; DEMONSTRATING its impact is an explicit, gated extra
step — the one place the engine steps beyond "prove, don't exploit" — because it
issues a real STATE-CHANGING request against the target.

It is target-agnostic and DYNAMIC by design. The operator declares only INTENT (an
:class:`ImpactAction`: a ``match`` substring — "delete" — and the ``params`` that
pick the object — ``username=carlos``). Sentinel then:

  1. fetches the discovery page (default: the confirmed breach route, e.g.
     ``/admin``) WITH the forged token — the page the bypass just unlocked,
  2. parses that LIVE page for the link or form whose href/action/text contains
     ``match``, preferring the candidate that already carries every ``params``
     value (the exact per-object action, ``…/delete?username=carlos``),
  3. builds the concrete request off the discovered element (never a hardcoded
     route) and issues it with the forged token, then issues the SAME action
     anonymously as a negative control — so the demonstration is itself a
     differential (the action required the forged privilege), not a blind fire.

Everything is recorded as ordinary probes on the SAME graph and scoped to the
confirmed hypothesis, so the report renders the impact as additional
steps-to-reproduce with the forged credential header masked. The operator-declared
params are ground truth (not secret); the forged token is the only secret and it
rides the request header, redacted in every report. The HTTP executor is injected,
so the whole module is offline-testable with zero network.
"""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from ..models import Experiment, HttpRequestSpec
from .broken_auth_policy import ImpactAction


@dataclass(frozen=True)
class ImpactObservation:
    """Token-safe record of an exercised privileged action. Reports PRESENCE and
    the (operator-declared) action URL; never a credential value."""

    attempted: bool = False
    discovered: bool = False
    performed: bool = False          # forged action returned a success/redirect status
    privileged: bool = False         # anonymous caller was DENIED the same action
    method: str = ""
    url: str = ""                    # the discovered action URL (params are declared, not secret)
    discovered_from: str = ""
    forged_status: "int | None" = None
    anon_status: "int | None" = None
    note: str = ""

    @property
    def demonstrated(self) -> bool:
        """The impact is DEMONSTRATED when the forged token performed the action
        AND an anonymous caller could not — the state change is attributable to the
        forged privilege, mirroring the class's own three-probe honesty."""
        return self.performed and self.privileged


# ---- dynamic discovery: parse the live page the forged token unlocked -------


class _ActionParser(HTMLParser):
    """Collect anchors (href + visible text) and forms (action, method, inputs) —
    the two shapes a privileged action takes in a rendered admin page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[dict] = []
        self.forms: list[dict] = []
        self._form: dict | None = None
        self._anchor: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and "href" in a:
            self._anchor = {"href": a["href"], "text": ""}
            self.anchors.append(self._anchor)
        elif tag == "form":
            self._form = {"action": a.get("action", ""),
                          "method": (a.get("method", "GET") or "GET").upper(),
                          "inputs": [], "text": ""}
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None:
            self._form["inputs"].append({
                "name": a.get("name", ""),
                "type": a.get("type", "text").lower(),
                "value": a.get("value", ""),
            })
        elif tag == "button" and self._form is not None:
            self._form["text"] += " " + a.get("value", "")

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag == "a":
            self._anchor = None
        elif tag == "form":
            self._form = None

    def handle_data(self, data):
        if self._anchor is not None:
            self._anchor["text"] += data
        elif self._form is not None:
            self._form["text"] += data


@dataclass(frozen=True)
class _Candidate:
    method: str
    url: str
    body: "str | None"


def _with_query(url: str, params: tuple[tuple[str, str], ...]) -> str:
    """Return ``url`` with ``params`` merged into its query string (declared values
    OVERRIDE any already present, so the exact object is targeted)."""
    if not params:
        return url
    sp = urlsplit(url)
    existing = dict(parse_qsl(sp.query, keep_blank_values=True))
    for name, value in params:
        existing[name] = value
    return urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(existing), sp.fragment))


def _form_body(inputs, params) -> str:
    """A form body: every carried input value verbatim, with declared params mapped
    onto matching field names (or appended when the form has no such field)."""
    body = {inp["name"]: inp["value"] for inp in inputs if inp["name"]}
    for name, value in params:
        body[name] = value
    return urlencode(body)


def _score(haystack: str, match: str, params) -> int:
    """How well a candidate fits the declared intent: it MUST contain ``match``
    (when given); +1 for each declared param value it already carries, so the exact
    per-object action outranks a generic one. ``-1`` means "does not match"."""
    hay = haystack.lower()
    if match and match.lower() not in hay:
        return -1
    return sum(1 for _, value in params if value and str(value).lower() in hay)


def select_action(html: str, base_url: str, impact: ImpactAction) -> "_Candidate | None":
    """Discover the privileged action on a live page. Returns the concrete request
    to issue, or ``None`` when nothing matches the declared intent (an honest miss —
    Sentinel then reports the bypass without a demonstrated action, never a guess)."""
    parser = _ActionParser()
    try:
        parser.feed(html or "")
    except Exception:  # noqa: BLE001 — a malformed page is a miss, never a crash
        return None

    best: "_Candidate | None" = None
    best_score = -1
    for anchor in parser.anchors:
        haystack = f"{anchor['href']} {anchor['text']}"
        score = _score(haystack, impact.match, impact.params)
        if score > best_score:
            url = _with_query(urljoin(base_url, anchor["href"]), impact.params)
            best, best_score = _Candidate(method="GET", url=url, body=None), score
    for form in parser.forms:
        names = " ".join(inp["name"] for inp in form["inputs"])
        haystack = f"{form['action']} {form['text']} {names}"
        score = _score(haystack, impact.match, impact.params)
        if score > best_score:
            action_url = urljoin(base_url, form["action"] or base_url)
            method = form["method"] or "POST"
            if method == "GET":
                cand = _Candidate(method="GET",
                                  url=_with_query(action_url, impact.params), body=None)
            else:
                cand = _Candidate(method=method, url=action_url,
                                  body=_form_body(form["inputs"], impact.params))
            best, best_score = cand, score
    return best if best_score >= 0 else None


# ---- probe recording (same machinery the prove-chain uses) ------------------


def _join_url(target_base: str, path: str) -> str:
    if "://" in path:
        return path
    base = target_base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def _run_probe(graph, executor, *, hypothesis_id, identity, tag, method, url,
               headers, body=None):
    """Issue one impact probe, record it on the graph scoped to the confirmed
    hypothesis (so the report renders it as a step), and return
    ``(status_code, body_text)`` read back off the recorded evidence."""
    request_headers = tuple(headers)
    if body is not None:
        request_headers = request_headers + (
            ("Content-Type", "application/x-www-form-urlencoded"),)
    experiment = Experiment(
        id=f"exp:broken-auth-{tag}:{hypothesis_id}",
        hypothesis_id=hypothesis_id,
        kind="broken_auth_check",
        description=f"Broken-authentication {tag} probe for {hypothesis_id}.",
        status="PLANNED",
        request=HttpRequestSpec(
            method=method,
            url=url,
            headers=request_headers,
            body=body,
            principal_id=getattr(identity, "principal_id", None),
            resource_id=getattr(identity, "resource_id", None),
            action=getattr(identity, "action", None),
        ),
        capability_id="broken_auth.broken_auth_check",
        action=f"probe_broken_auth_{tag}",
    )
    graph.add_experiment(experiment)

    result = executor.execute(experiment)
    body_text = ""
    for evidence in result.evidence:
        graph.add_evidence(evidence)
        data = getattr(evidence, "data", {}) or {}
        if isinstance(data, dict) and data.get("mode") == "http":
            body_text = data.get("response_body_text", "") or body_text

    graph.add_experiment(Experiment(
        id=experiment.id,
        hypothesis_id=experiment.hypothesis_id,
        kind=experiment.kind,
        description=experiment.description,
        status=result.status,
        evidence_ids=tuple(evidence.id for evidence in result.evidence),
        request=experiment.request,
        capability_id=experiment.capability_id,
        action=experiment.action,
    ))

    raw_code = dict(result.metadata).get("status_code")
    code = int(raw_code) if raw_code is not None else None
    return code, body_text


# ---- the stage: fetch → discover → exercise (forged) → deny (anon) ----------


def exercise_impact(target_base, *, impact: ImpactAction, forged_headers, graph,
                    executor, hypothesis_id, identity, breach_url, breach_method="GET",
                    success_statuses=tuple(range(200, 300))) -> ImpactObservation:
    """Demonstrate the concrete impact of a CONFIRMED forgery.

    Fetch the discovery page (default: the breach route) with the forged token,
    dynamically discover the declared privileged action, issue it with the forged
    token, then issue the SAME action anonymously as a negative control. Records
    every request on ``graph`` scoped to ``hypothesis_id`` so the report renders
    them (with the credential header masked). ``forged_headers`` is the exact header
    tuple the breach probe used — reused, NEVER re-derived. Any fault degrades to a
    token-safe observation; it never raises into the caller."""
    if impact is None or not impact.declared:
        return ImpactObservation(note="no impact action declared")

    success = set(success_statuses)

    # Resolve the concrete action: an explicit route, else discover it live.
    if impact.action is not None:
        method = impact.action.method or "GET"
        url = _join_url(target_base, impact.action.path)
        if method == "GET":
            url, body = _with_query(url, impact.params), None
        else:
            body = _form_body((), impact.params)
        discovered_from = "operator-declared action"
        discovered = True
    else:
        discover_path = impact.discover.path if impact.discover is not None else None
        discover_url = (_join_url(target_base, discover_path)
                        if discover_path else breach_url)
        discover_method = (impact.discover.method
                           if impact.discover is not None else "GET")
        try:
            _, page = _run_probe(
                graph, executor, hypothesis_id=hypothesis_id, identity=identity,
                tag="impact_discover", method=discover_method, url=discover_url,
                headers=forged_headers)
        except Exception as exc:  # noqa: BLE001
            return ImpactObservation(attempted=True, discovered_from=discover_url,
                                     note=f"discovery fetch failed: {type(exc).__name__}")
        candidate = select_action(page, discover_url, impact)
        if candidate is None:
            return ImpactObservation(
                attempted=True, discovered_from=discover_url,
                note=f"no privileged action matching {impact.match!r} found on the "
                     "unlocked page — bypass proven, no impact demonstrated")
        method, url, body = candidate.method, candidate.url, candidate.body
        discovered_from = discover_url
        discovered = True

    # Exercise the action WITH the forged token — the real state change.
    try:
        forged_code, _ = _run_probe(
            graph, executor, hypothesis_id=hypothesis_id, identity=identity,
            tag="impact", method=method, url=url, headers=forged_headers, body=body)
    except Exception as exc:  # noqa: BLE001
        return ImpactObservation(attempted=True, discovered=discovered, method=method,
                                 url=url, discovered_from=discovered_from,
                                 note=f"impact action failed: {type(exc).__name__}")

    # Anonymous negative control: the SAME action with NO token MUST be denied,
    # proving the state change was attributable to the forged privilege.
    anon_code = None
    try:
        anon_code, _ = _run_probe(
            graph, executor, hypothesis_id=hypothesis_id, identity=identity,
            tag="impact_denied", method=method, url=url, headers=(), body=body)
    except Exception:  # noqa: BLE001 — the anon control is best-effort
        anon_code = None

    performed = forged_code is not None and (
        forged_code in success or 300 <= forged_code < 400)
    privileged = anon_code is not None and not (
        anon_code in success or 300 <= anon_code < 400)
    note = (f"exercised {method} {url} with the forged token → {forged_code}"
            + (f"; anonymous → {anon_code} (denied)" if privileged
               else (f"; anonymous → {anon_code}" if anon_code is not None else "")))
    return ImpactObservation(
        attempted=True, discovered=discovered, performed=performed,
        privileged=privileged, method=method, url=url,
        discovered_from=discovered_from, forged_status=forged_code,
        anon_status=anon_code, note=note)
