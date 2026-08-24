"""
Offline, network-free proof of the broken-authentication (JWT-forgery) class
and its honest PATCH + PROVE remediation. No real target is contacted for the
unit tests: a canned executor keys each probe on the ``Authorization`` token
VALUE — the genuine captured token (control), a forged token (breach), or no
header at all (anonymous baseline) — so the three-probe differential is pinned
deterministically:

  * a declared route becomes an OPEN hypothesis, never a finding;
  * the PURE judge returns VALIDATED only when the control probe SUCCEEDS (the
    genuine token works, so the route is token-authenticated) AND the FORGED
    token is ALSO accepted AND an anonymous caller is DENIED that same route —
    so the acceptance is attributable to a token Sentinel minted, not a public
    route; DISPROVED when the forged token is refused (validation holds); and
    INCONCLUSIVE when the control itself fails (dead/cookie session) or an
    anonymous caller is ALSO accepted (public route) — nothing is claimed;
  * remediation is HONEST: a guard-provable forgery (alg=none / unsigned) earns
    a jwt shape-guard whose fix is PROVEN only when the same judge flips
    VALIDATED -> DISPROVED, while a validly-signed forgery (hs256_confusion /
    weak_secret) is ADVISORY_ONLY — Sentinel never stands a shield it cannot
    earn — and verification NEVER mutates the confirmed hypothesis or finding.

One localhost integration test stands the real reverse proxy in front of a stub
that naively accepts ANY bearer token (the flaw) but denies anonymous callers,
and proves the jwt shape-guard refuses the forged alg=none token (403) while
still forwarding the genuinely-signed control token — the honest fix.
"""

import base64
import hashlib
import hmac
import json
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.security_graph.execution import ExperimentExecutor
from app.security_graph.graph import SecurityGraph
from app.security_graph.models import Evidence, ExecutionResult
from app.security_graph.broken_auth import (
    decode_jwt,
    derive_forgery,
    judge_broken_auth,
    parse_broken_auth_policy,
    remediate_broken_auth_and_prove,
    render_broken_auth_artifacts,
    run_broken_auth_investigation,
    strip_bearer,
    synthesize_broken_auth_remediation,
)

TARGET_BASE = "http://127.0.0.1:3000"
PROTECTED_PATH = "/rest/user/whoami"
WEAK_SECRET = "secret"
# hs256_confusion needs SOME public-key material; the forge module only uses its
# bytes as an HMAC secret, so any non-empty string exercises the derivation.
PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\nMFkwEwYH...fake...==\n-----END PUBLIC KEY-----"


def _b64url(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _hs256(header: dict, payload: dict, secret: str) -> str:
    """Mint a genuine 3-part HS256 JWS signed with `secret`."""
    hseg = _b64url(header)
    pseg = _b64url(payload)
    signing_input = f"{hseg}.{pseg}".encode("ascii")
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sseg = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
    return f"{hseg}.{pseg}.{sseg}"


# A genuine, validly-signed 3-part token (HS256 under the weak secret). It is a
# real JWS — decode_jwt accepts it — and its signature is crackable from a
# dictionary that contains WEAK_SECRET, so it exercises every forgery strategy.
GENUINE = _hs256(
    {"alg": "HS256", "typ": "JWT"},
    {"sub": "user-7", "role": "user"},
    WEAK_SECRET,
)


class _CannedBrokenAuthExecutor(ExperimentExecutor):
    """A network-free broken-auth executor keyed on the Authorization token.

    The judge reads the single ``mode=="http"`` evidence's ``status_code`` per
    probe, so this supplies the observed codes directly. It models the three
    probes exactly as the differential demands: the *control* probe carries the
    GENUINE token, the *breach* probe carries a FORGED token, and the anonymous
    *baseline* probe carries no Authorization header. A header whose bare token
    equals the genuine one is scored ``control_status``; any other bearer token
    is scored ``breach_status``; a headerless request is scored
    ``baseline_status`` (401 — an anonymous caller is denied).
    """

    kind = "broken_auth_check"

    def __init__(
        self,
        genuine_token,
        *,
        control_status=200,
        breach_status=200,
        baseline_status=401,
    ):
        self._genuine = genuine_token
        self._control = control_status
        self._breach = breach_status
        self._baseline = baseline_status

    def execute(self, experiment):
        req = experiment.request
        url = req.url if req else ""
        auth = ""
        for name, value in (req.headers if req is not None else ()):
            if str(name).lower() == "authorization":
                auth = str(value)
                break
        if not auth:
            status = self._baseline
        elif strip_bearer(auth) == self._genuine:
            status = self._control
        else:
            status = self._breach
        evidence = Evidence(
            id=f"ev:broken-auth:{experiment.id}",
            source="http_response",
            data={
                "mode": "http",
                "status_code": status,
                "response_headers": {},
                "url": url,
            },
            confidence=1.0,
        )
        return ExecutionResult(
            experiment_id=experiment.id,
            status="COMPLETED",
            evidence=(evidence,),
            metadata=(("status_code", str(status)),),
        )

def _policy(
    forgery="alg_none",
    *,
    public_key="",
    secret_candidates=(),
    success_statuses=None,
    genuine=GENUINE,
    path=PROTECTED_PATH,
):
    """Build a one-check broken-auth matrix whose principal carries `genuine`."""
    check = {
        "forgery": forgery,
        "route": {"method": "GET", "path": path},
        "severity": "HIGH",
    }
    if public_key:
        check["public_key"] = public_key
    if secret_candidates:
        check["secret_candidates"] = list(secret_candidates)
    matrix = {
        "principal": {
            "name": "authenticated",
            "headers": [["Authorization", f"Bearer {genuine}"]],
            "role": "user",
        },
        "checks": [check],
    }
    if success_statuses is not None:
        matrix["success_statuses"] = success_statuses
    return parse_broken_auth_policy({"broken_auth_matrix": matrix})


def _resolved_graph(
    forgery="alg_none",
    *,
    control_status=200,
    breach_status=200,
    baseline_status=401,
    **policy_kw,
):
    """Seed one route and drive it to a verdict with canned probe codes."""
    graph = SecurityGraph()
    results = run_broken_auth_investigation(
        graph,
        _policy(forgery, **policy_kw),
        target_base=TARGET_BASE,
        executor=_CannedBrokenAuthExecutor(
            policy_kw.get("genuine", GENUINE),
            control_status=control_status,
            breach_status=breach_status,
            baseline_status=baseline_status,
        ),
    )
    return graph, results


def _confirmed_finding(graph):
    findings = list(graph.findings_for(kind="broken_auth", status="OPEN"))
    assert len(findings) == 1
    return findings[0]


# --- forge (pure, offline) --------------------------------------------------

def test_decode_jwt_accepts_real_token_rejects_non_jwt():
    parts = decode_jwt(GENUINE)
    assert parts is not None
    assert parts.header["alg"] == "HS256"
    assert parts.payload["sub"] == "user-7"
    assert decode_jwt("not-a-jwt") is None
    # tolerate a Bearer wrapper
    assert decode_jwt(f"Bearer {GENUINE}") is not None


def _marker_of(token: str):
    parts = decode_jwt(token)
    return parts.payload.get("sentinel_forge") if parts is not None else None


def test_alg_none_forgery_is_guard_provable_and_marked():
    result = derive_forgery(GENUINE, "alg_none")
    assert result.token is not None
    assert result.guard_provable is True
    forged = decode_jwt(result.token)
    assert forged is not None
    assert forged.header["alg"] == "none"
    assert forged.signature_seg == ""  # empty signature, trailing dot
    assert _marker_of(result.token) == "sentinel"  # benign forge marker


def test_unsigned_forgery_is_two_part_and_guard_provable():
    result = derive_forgery(GENUINE, "unsigned")
    assert result.token is not None
    assert result.guard_provable is True
    assert len(result.token.split(".")) == 2  # header.payload, no signature
    assert _marker_of(result.token) == "sentinel"


def test_hs256_confusion_needs_public_key_and_is_not_guard_provable():
    # No material -> not derivable, so no probe is ever seeded.
    assert derive_forgery(GENUINE, "hs256_confusion").token is None
    result = derive_forgery(GENUINE, "hs256_confusion", public_key=PUBLIC_KEY)
    assert result.token is not None
    assert result.guard_provable is False  # validly signed -> advisory only
    assert _marker_of(result.token) == "sentinel"


def test_weak_secret_cracks_from_dictionary_else_none():
    cracked = derive_forgery(
        GENUINE, "weak_secret", secret_candidates=("wrong", WEAK_SECRET, "nope")
    )
    assert cracked.token is not None
    assert cracked.cracked_secret == WEAK_SECRET
    assert cracked.guard_provable is False
    # A strong secret no candidate cracks yields no forgery (never a false claim).
    strong = derive_forgery(GENUINE, "weak_secret", secret_candidates=("a", "b"))
    assert strong.token is None
    assert strong.cracked_secret is None


def test_forgery_from_non_jwt_is_never_derivable():
    for strategy in ("alg_none", "unsigned", "hs256_confusion", "weak_secret"):
        assert derive_forgery("opaque-session-id", strategy).token is None


# --- parse ------------------------------------------------------------------

def test_parse_reads_principal_and_check():
    policy = _policy("alg_none")
    assert policy.principal is not None
    assert policy.principal.name == "authenticated"
    assert len(policy.checks) == 1
    check = policy.checks[0]
    assert check.forgery == "alg_none"
    assert check.method == "GET" and check.path == PROTECTED_PATH


def test_parse_rejects_unknown_forgery():
    with pytest.raises(ValueError):
        parse_broken_auth_policy(
            {
                "broken_auth_matrix": {
                    "principal": {"name": "authenticated"},
                    "checks": [
                        {"forgery": "quantum", "route": {"path": PROTECTED_PATH}}
                    ],
                }
            }
        )


def test_empty_matrix_is_legal():
    policy = parse_broken_auth_policy({"broken_auth_matrix": {"checks": []}})
    assert policy.checks == ()

# --- seed honesty (no probe without a derivable forgery) --------------------

def test_non_jwt_session_token_seeds_nothing():
    # The captured token is not a JWT -> no forgery is derivable -> no probe is
    # seeded and no result/finding is produced (the honest failure mode).
    graph, results = _resolved_graph("alg_none", genuine="opaque-cookie-value")
    assert results == []
    assert not list(graph.hypotheses_for(kind="broken_auth", status="OPEN"))


def test_uncrackable_weak_secret_seeds_nothing():
    graph, results = _resolved_graph(
        "weak_secret", secret_candidates=("aaa", "bbb"), breach_status=200
    )
    assert results == []
    assert not list(graph.findings_for(kind="broken_auth", status="OPEN"))


# --- seed + PURE three-probe judge ------------------------------------------

def test_forged_token_accepted_is_validated_and_confirmed():
    graph, results = _resolved_graph("alg_none", breach_status=200)
    assert len(results) == 1
    assert results[0].status == "VALIDATED"
    assert results[0].control_status_code == 200
    assert results[0].breach_status_code == 200
    assert results[0].baseline_status_code == 401
    assert results[0].guard_provable is True
    assert graph.hypotheses[results[0].hypothesis_id].status == "CONFIRMED"

    finding = _confirmed_finding(graph)
    assert finding.kind == "broken_auth"
    assert finding.severity == "HIGH"


def test_forged_token_rejected_is_disproved_no_finding():
    graph, results = _resolved_graph("alg_none", breach_status=403)
    assert results[0].status == "DISPROVED"
    assert graph.hypotheses[results[0].hypothesis_id].status != "CONFIRMED"
    assert not list(graph.findings_for(kind="broken_auth", status="OPEN"))


def test_dead_control_session_is_inconclusive_no_finding():
    # The genuine token does NOT succeed -> the route is not proven token-
    # authenticated -> a forged 200 cannot be attributed, so nothing is claimed.
    graph, results = _resolved_graph(
        "alg_none", control_status=401, breach_status=200
    )
    assert results[0].status == "INCONCLUSIVE"
    assert graph.hypotheses[results[0].hypothesis_id].status == "OPEN"
    assert not list(graph.findings_for(kind="broken_auth", status="OPEN"))


def test_public_route_confound_is_inconclusive_no_finding():
    # The forged token is accepted, but so is an anonymous caller: the route is
    # public, so the acceptance is not attributable to a validation flaw. The
    # anonymous negative control catches the confound a bare status would miss.
    graph, results = _resolved_graph(
        "alg_none", breach_status=200, baseline_status=200
    )
    assert results[0].status == "INCONCLUSIVE"
    assert results[0].baseline_status_code == 200
    assert graph.hypotheses[results[0].hypothesis_id].status == "OPEN"
    assert not list(graph.findings_for(kind="broken_auth", status="OPEN"))


def test_pure_judge_reads_the_three_probe_differential_directly():
    # Drive to a confirmed graph, then re-run the PURE judge against the same
    # recorded probes and assert the verdict is a deterministic function of them.
    graph, results = _resolved_graph("alg_none", breach_status=200)
    hyp = graph.hypotheses[results[0].hypothesis_id]
    judgment = judge_broken_auth(
        graph,
        hypothesis=hyp,
        control_experiment_id=f"exp:broken-auth-control:{hyp.id}",
        breach_experiment_id=f"exp:broken-auth-breach:{hyp.id}",
        baseline_experiment_id=f"exp:broken-auth-baseline:{hyp.id}",
    )
    assert judgment.status == "VALIDATED"
    assert judgment.contradiction_kind == "broken_auth"
    assert judgment.observed is True  # the forged token was accepted
    assert judgment.expected is False  # a forged token MUST NOT be accepted

# --- synthesize + artifacts -------------------------------------------------

def test_synthesize_broken_auth_remediation_from_confirmed():
    graph, _ = _resolved_graph("alg_none", breach_status=200)
    plan = synthesize_broken_auth_remediation(graph, _confirmed_finding(graph))
    assert plan is not None
    assert plan.rule.method == "GET" and plan.rule.path == PROTECTED_PATH
    assert plan.rule.param == "Authorization"
    assert plan.rule.location == "header"
    assert plan.rule.guard_provable is True
    assert plan.upstream_base == TARGET_BASE
    assert plan.breach_url == TARGET_BASE + PROTECTED_PATH


def test_synthesize_ignores_non_broken_auth_finding():
    graph, _ = _resolved_graph("alg_none", breach_status=200)
    foreign = replace(_confirmed_finding(graph), kind="privilege_escalation")
    assert synthesize_broken_auth_remediation(graph, foreign) is None


def test_render_artifacts_non_empty_and_name_the_route():
    graph, _ = _resolved_graph("alg_none", breach_status=200)
    plan = synthesize_broken_auth_remediation(graph, _confirmed_finding(graph))
    artifacts = render_broken_auth_artifacts(plan.rule, plan.upstream_base)
    for config in (
        artifacts.portable_json,
        artifacts.nginx,
        artifacts.modsecurity,
        artifacts.caddy,
    ):
        assert config.strip()
        assert PROTECTED_PATH in config
    assert plan.upstream_base in artifacts.nginx


# --- remediate + PROVE (injected executors, no live proxy) ------------------

def test_remediate_alg_none_fix_proven_and_isolated():
    graph, _ = _resolved_graph("alg_none", breach_status=200)
    finding = _confirmed_finding(graph)
    hyp_id = finding.hypothesis_id

    outcome = remediate_broken_auth_and_prove(
        graph,
        finding,
        # before: the forged token is still accepted -> VALIDATED
        before_executor=_CannedBrokenAuthExecutor(GENUINE, breach_status=200),
        # after: the shield refuses the forged token, control still works -> DISPROVED
        after_executor=_CannedBrokenAuthExecutor(GENUINE, breach_status=403),
        use_enforcer=False,
    )

    assert outcome.result == "FIX_PROVEN"
    assert outcome.verification.before_status == "VALIDATED"
    assert outcome.verification.after_status == "DISPROVED"

    # Isolation: the confirmed hypothesis/finding must be untouched by verify.
    assert graph.hypotheses[hyp_id].status == "CONFIRMED"
    assert _confirmed_finding(graph).status == "OPEN"


def test_remediate_alg_none_fix_failed_when_forgery_still_accepted():
    graph, _ = _resolved_graph("alg_none", breach_status=200)
    outcome = remediate_broken_auth_and_prove(
        graph,
        _confirmed_finding(graph),
        before_executor=_CannedBrokenAuthExecutor(GENUINE, breach_status=200),
        after_executor=_CannedBrokenAuthExecutor(GENUINE, breach_status=200),
        use_enforcer=False,
    )
    assert outcome.result == "FIX_FAILED"
    assert outcome.verification.after_status == "VALIDATED"


def test_remediate_alg_none_not_proven_without_the_flip():
    # The after-shield judge is DISPROVED, but the forgery did NOT reproduce on
    # the pre-fix re-probe (before != VALIDATED). FIX_PROVEN requires the full
    # VALIDATED -> DISPROVED flip, never after == DISPROVED alone.
    graph, _ = _resolved_graph("alg_none", breach_status=200)
    outcome = remediate_broken_auth_and_prove(
        graph,
        _confirmed_finding(graph),
        before_executor=_CannedBrokenAuthExecutor(GENUINE, breach_status=403),
        after_executor=_CannedBrokenAuthExecutor(GENUINE, breach_status=403),
        use_enforcer=False,
    )
    assert outcome.result == "FIX_FAILED"
    assert outcome.verification.before_status == "DISPROVED"
    assert not outcome.verification.proven


def test_remediate_hs256_confusion_is_advisory_only():
    # A validly-signed forgery is invisible to a shape-guard: honest ADVISORY,
    # never a manufactured proof and never labelled a failure.
    graph, _ = _resolved_graph(
        "hs256_confusion", public_key=PUBLIC_KEY, breach_status=200
    )
    outcome = remediate_broken_auth_and_prove(
        graph, _confirmed_finding(graph), use_enforcer=False
    )
    assert outcome.result == "ADVISORY_ONLY"
    assert outcome.plan is not None and outcome.artifacts is not None
    assert outcome.verification is None


def test_remediate_weak_secret_is_advisory_only():
    graph, _ = _resolved_graph(
        "weak_secret",
        secret_candidates=("wrong", WEAK_SECRET),
        breach_status=200,
    )
    outcome = remediate_broken_auth_and_prove(
        graph, _confirmed_finding(graph), use_enforcer=False
    )
    assert outcome.result == "ADVISORY_ONLY"


def test_remediate_non_broken_auth_finding_is_not_applicable():
    graph, _ = _resolved_graph("alg_none", breach_status=200)
    foreign = replace(_confirmed_finding(graph), kind="privilege_escalation")
    outcome = remediate_broken_auth_and_prove(graph, foreign, use_enforcer=False)
    assert outcome.result == "NOT_APPLICABLE"

# --- live integration: real reverse proxy refuses the forged token ----------

class _StubJwtUpstream(BaseHTTPRequestHandler):
    """The pre-fix vulnerable target.

    It NAIVELY accepts ANY bearer token without verifying the signature (the
    broken-auth flaw — an alg=none forgery is honoured just like a genuine
    token), but denies an anonymous caller (401 when no ``Authorization``
    header). The anonymous denial is what lets the three-probe judge attribute
    the forged-token acceptance to a validation flaw rather than a public route.
    """

    def log_message(self, *args, **kwargs):
        return

    def _respond(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.headers.get("Authorization"):
            self._respond(401, b'{"error":"unauthorized"}')
            return
        self._respond(200, b"{}")


def test_live_enforcer_refuses_forged_token_but_forwards_genuine():
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _StubJwtUpstream)
    upstream.daemon_threads = True
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        upstream_base = f"http://127.0.0.1:{upstream.server_address[1]}"

        # Seed a fresh graph bound to the live stub and drive it to a confirmed
        # broken-auth via the REAL http executor (no canned codes here).
        graph = SecurityGraph()
        run_broken_auth_investigation(
            graph,
            _policy("alg_none"),
            target_base=upstream_base,
        )
        finding = _confirmed_finding(graph)

        # Prove the fix through the REAL reverse proxy + jwt shape-guard.
        outcome = remediate_broken_auth_and_prove(graph, finding, use_enforcer=True)

        assert outcome.result == "FIX_PROVEN"
        assert outcome.verification.before_status == "VALIDATED"
        assert outcome.verification.after_status == "DISPROVED"
        assert outcome.verification.observed_status_code == 403
    finally:
        upstream.shutdown()
        upstream.server_close()

