"""
Offline, network-free proof of the provable-chaining capstone (SQLi ⇒ IDOR/BOLA).

No real target is contacted. A canned injection executor reproduces the boolean
differential *and* attaches a ``response_body_text`` to the tautology "dump" arm
(the arm the pure injection judge selects as VALIDATED) that leaks other objects'
ids — exactly what a real injection dumps. A canned BOLA executor then models the
downstream object endpoint. Together they pin the honest edge contract:

  * a leaked id is extracted ONLY from the confirmed injection's real recorded
    evidence (never invented);
  * a chain is emitted ONLY when the real leaked id makes the UNCHANGED privesc
    judge fire VALIDATED while a same-shaped decoy id does NOT (the decoy wall);
  * a merely-leaked id whose object is not actually reachable, and a route that
    answers for any id, both yield NO chain.
"""

import json
from urllib.parse import parse_qsl, urlsplit

from app.security_graph.execution import ExperimentExecutor
from app.security_graph.graph import SecurityGraph
from app.security_graph.models import Evidence, ExecutionResult
from app.security_graph.injection import (
    parse_injection_policy,
    run_injection_investigation,
)
from app.security_graph.chaining import (
    BolaChainTarget,
    ChainFinding,
    ChainPolicy,
    compose_chains,
    decoy_value,
    escalate,
    extract_artifacts,
    inject_artifact,
    max_severity,
    parse_chain_targets,
)

import pytest


TARGET_BASE = "http://127.0.0.1:3000"
SEARCH_PATH = "/rest/products/search"
BASELINE_VALUE = "apple"
CONTROL_PATH = "/api/whoami"
BASKET_TEMPLATE = "/rest/basket/{id}"
ATTACKER_HEADERS = (("Authorization", "Bearer chain-token"),)
VICTIM_ID = "2"

_BASE_BODY = 512
_ALL_BODY = 4096
_ZERO_BODY = 64

# The rows a boolean-tautology dump leaks (the injection's TRUE arm). The
# attacker can cross-tenant-read basket id "2" specifically (the IDOR).
_LEAKED_ROWS = [
    {"id": "1", "user": "admin"},
    {"id": VICTIM_ID, "user": "victim"},
    {"id": "3", "user": "carol"},
]
_LEAKED_JSON = json.dumps(_LEAKED_ROWS)


def _injectable_body(value):
    """Model a VULNERABLE string-context search: length encodes the row count."""
    quote = "'" if "'" in value else ('"' if '"' in value else None)
    if quote is None:
        return 200, _BASE_BODY
    tail = value.split(quote, 1)[1].lower()
    truthy = ("1'='1" in tail) or ("1=1" in tail) or ('1"="1' in tail)
    falsy = ("1'='2" in tail) or ("1=2" in tail) or ('1"="2' in tail)
    has_or = " or " in f" {tail} "
    has_and = " and " in f" {tail} "
    if has_or and truthy:
        return 200, _ALL_BODY
    if has_or and falsy:
        return 200, _BASE_BODY
    if has_and and truthy:
        return 200, _BASE_BODY
    if has_and and falsy:
        return 200, _ZERO_BODY
    return 200, _BASE_BODY


class _CannedInjectionExecutor(ExperimentExecutor):
    """Reproduce the boolean differential and leak ids on the dump arm only."""

    kind = "injection_check"

    def __init__(self, param="q"):
        self._param = param

    def _value(self, experiment):
        req = experiment.request
        if req is None:
            return ""
        query = urlsplit(req.url).query
        return dict(parse_qsl(query, keep_blank_values=True)).get(self._param, "")

    def execute(self, experiment):
        value = self._value(experiment)
        status, length = _injectable_body(value)
        # Only the boolean-tautology "dump" arm (the VALIDATED arm) leaks other
        # objects' ids; benign arms carry a row with no id key.
        body_text = _LEAKED_JSON if length == _ALL_BODY else json.dumps(
            [{"name": "apple juice"}]
        )
        evidence = Evidence(
            id=f"ev:injection:{experiment.id}",
            source="http_response",
            data={
                "mode": "http",
                "status_code": status,
                "response_body_length": length,
                "response_body_text": body_text,
                "url": experiment.request.url if experiment.request else "",
            },
            confidence=1.0,
        )
        return ExecutionResult(
            experiment_id=experiment.id,
            status="COMPLETED",
            evidence=(evidence,),
            metadata=(("status_code", str(status)),),
        )


def _make_bola_executor(grant):
    """Build a canned downstream object endpoint from a grant(path, has_auth)."""

    class _CannedBolaExecutor(ExperimentExecutor):
        kind = "privilege_escalation_check"

        def execute(self, experiment):
            req = experiment.request
            path = urlsplit(req.url).path
            has_auth = any(
                key.lower() == "authorization" and bool(value)
                for key, value in (req.headers or ())
            )
            status = grant(path, has_auth)
            length = 256 if status == 200 else 64
            evidence = Evidence(
                id=f"ev:bola:{experiment.id}",
                source="http_response",
                data={
                    "mode": "http",
                    "status_code": status,
                    "response_body_length": length,
                    "response_body_text": "{}",
                    "url": req.url,
                },
                confidence=1.0,
            )
            return ExecutionResult(
                experiment_id=experiment.id,
                status="COMPLETED",
                evidence=(evidence,),
                metadata=(("status_code", str(status)),),
            )

    return _CannedBolaExecutor()


# --- grant models (what the downstream object endpoint returns) -------------

def _grant_specific_idor(path, has_auth):
    """Only basket id 2 is cross-readable (a real IDOR); anon always denied."""
    if path == CONTROL_PATH:
        return 200 if has_auth else 401
    if path == f"/rest/basket/{VICTIM_ID}":
        return 200 if has_auth else 401
    return 404 if has_auth else 401


def _grant_any_authed(path, has_auth):
    """Any basket id answers for a logged-in caller (a per-user route that
    ignores the id) — so a decoy id validates too and the edge collapses."""
    if path == CONTROL_PATH:
        return 200 if has_auth else 401
    if path.startswith("/rest/basket/"):
        return 200 if has_auth else 401
    return 404


def _grant_boundary_holds(path, has_auth):
    """No basket is cross-readable; every breach is denied even with a session."""
    if path == CONTROL_PATH:
        return 200 if has_auth else 401
    return 404 if has_auth else 401


# --- fixtures ---------------------------------------------------------------

def _confirmed_injection_graph():
    graph = SecurityGraph()
    policy = parse_injection_policy(
        {"injection_matrix": {"checks": [
            {"method": "GET", "path": SEARCH_PATH, "param": "q",
             "baseline_value": BASELINE_VALUE, "location": "query",
             "severity": "HIGH"},
        ]}}
    )
    run_injection_investigation(
        graph, policy, target_base=TARGET_BASE,
        executor=_CannedInjectionExecutor(),
    )
    return graph


def _bola_target():
    return BolaChainTarget(
        breach_path_template=BASKET_TEMPLATE,
        attacker_headers=ATTACKER_HEADERS,
        control_path=CONTROL_PATH,
        breach_method="GET",
        victim="victim",
        severity="HIGH",
    )


# --- artifact extraction (pure) --------------------------------------------

def test_extract_artifacts_reads_leaked_ids_from_true_arm():
    graph = _confirmed_injection_graph()
    finding = graph.findings_for(kind="injection", status="OPEN")[0]
    artifacts = extract_artifacts(graph, finding)
    values = {artifact.value for artifact in artifacts}
    assert {"1", "2", "3"} <= values
    for artifact in artifacts:
        assert artifact.kind == "leaked_object_id"
        assert artifact.source_kind == "injection"
        assert artifact.evidence_id  # points at the real TRUE-arm probe evidence
        assert graph.evidence[artifact.evidence_id].data["mode"] == "http"


def test_extract_artifacts_empty_for_non_injection_finding():
    from dataclasses import replace

    graph = _confirmed_injection_graph()
    finding = graph.findings_for(kind="injection", status="OPEN")[0]
    foreign = replace(finding, kind="cors_misconfig")
    assert extract_artifacts(graph, foreign) == []


def test_extract_artifacts_empty_when_no_recorded_evidence():
    from app.security_graph.models import SecurityFinding

    graph = SecurityGraph()
    ghost = SecurityFinding(
        id="finding:ghost", hypothesis_id="hyp:none", kind="injection",
        title="", claim="", severity="HIGH", confidence=0.9,
    )
    assert extract_artifacts(graph, ghost) == []


# --- consume helpers --------------------------------------------------------

def test_inject_artifact_substitutes_placeholder():
    assert inject_artifact("/rest/basket/{id}", "2") == "/rest/basket/2"
    assert inject_artifact("/u/{id}/x", "9", placeholder="{id}") == "/u/9/x"


def test_decoy_value_same_length_and_different():
    for value in ("2", "42", "abc", "a1b2", "0000", "user-77"):
        decoy = decoy_value(value)
        assert decoy != value
        assert len(decoy) == len(value)


def test_severity_helpers():
    assert max_severity("MEDIUM", "HIGH") == "HIGH"
    assert escalate("HIGH") == "CRITICAL"
    assert escalate("CRITICAL") == "CRITICAL"


# --- compose: the proven edge + the decoy wall ------------------------------

def test_compose_emits_proven_chain_for_specific_leaked_id():
    graph = _confirmed_injection_graph()
    chains = compose_chains(
        graph,
        bola_targets=(_bola_target(),),
        target_base=TARGET_BASE,
        executor=_make_bola_executor(_grant_specific_idor),
    )
    assert len(chains) == 1
    chain = chains[0]
    assert isinstance(chain, ChainFinding)
    assert chain.edge_proven is True
    assert chain.real_status == "VALIDATED"
    assert chain.decoy_status != "VALIDATED"
    assert chain.artifact.value == VICTIM_ID
    assert chain.breach_path == f"/rest/basket/{VICTIM_ID}"
    assert [link.kind for link in chain.links] == [
        "injection", "privilege_escalation"
    ]
    assert chain.links[0].status == "CONFIRMED"
    assert chain.links[1].status == "VALIDATED"
    # HIGH ∧ HIGH escalated one rung → CRITICAL
    assert chain.severity == "CRITICAL"


def test_compose_decoy_wall_suppresses_answer_for_any_id():
    # The route answers for ANY id when authenticated, so a same-shaped decoy id
    # ALSO validates → the edge is not load-bearing → no chain is emitted.
    graph = _confirmed_injection_graph()
    chains = compose_chains(
        graph,
        bola_targets=(_bola_target(),),
        target_base=TARGET_BASE,
        executor=_make_bola_executor(_grant_any_authed),
    )
    assert chains == []


def test_compose_no_chain_when_boundary_holds():
    # No basket is cross-readable: the real leaked id is denied too → downstream
    # DISPROVED → no chain (a merely-leaked id is not a false positive).
    graph = _confirmed_injection_graph()
    chains = compose_chains(
        graph,
        bola_targets=(_bola_target(),),
        target_base=TARGET_BASE,
        executor=_make_bola_executor(_grant_boundary_holds),
    )
    assert chains == []


def test_compose_no_source_finding_yields_no_chains():
    graph = SecurityGraph()  # nothing confirmed
    chains = compose_chains(
        graph,
        bola_targets=(_bola_target(),),
        target_base=TARGET_BASE,
        executor=_make_bola_executor(_grant_specific_idor),
    )
    assert chains == []


def test_compose_requires_placeholder_in_template():
    graph = _confirmed_injection_graph()
    chains = compose_chains(
        graph,
        bola_targets=(BolaChainTarget(
            breach_path_template="/rest/basket/no-placeholder",
            attacker_headers=ATTACKER_HEADERS,
            control_path=CONTROL_PATH,
        ),),
        target_base=TARGET_BASE,
        executor=_make_bola_executor(_grant_specific_idor),
    )
    assert chains == []


# --- chain-targets DATA parser (pure, target-agnostic) ----------------------

def _target_doc():
    return {
        "chain_targets": {
            "source_kind": "injection",
            "targets": [
                {
                    "breach": {"method": "GET", "path_template": BASKET_TEMPLATE},
                    "attacker_headers": {"Authorization": "Bearer chain-token"},
                    "control": {"method": "GET", "path": CONTROL_PATH},
                    "victim": "victim",
                    "severity": "HIGH",
                }
            ],
        }
    }


def test_parse_chain_targets_builds_bola_targets():
    policy = parse_chain_targets(_target_doc())
    assert isinstance(policy, ChainPolicy)
    assert policy.source_kind == "injection"
    assert len(policy.targets) == 1
    target = policy.targets[0]
    assert target.breach_path_template == BASKET_TEMPLATE
    assert target.attacker_headers == (("Authorization", "Bearer chain-token"),)
    assert target.control_path == CONTROL_PATH
    assert target.breach_method == "GET"
    assert target.victim == "victim"
    assert target.severity == "HIGH"
    assert target.placeholder == "{id}"


def test_parse_chain_targets_end_to_end_proves_chain():
    # The parsed operator DATA drives the SAME composer as the hand-built target.
    graph = _confirmed_injection_graph()
    policy = parse_chain_targets(_target_doc())
    chains = compose_chains(
        graph,
        bola_targets=policy.targets,
        target_base=TARGET_BASE,
        executor=_make_bola_executor(_grant_specific_idor),
        source_kind=policy.source_kind,
    )
    assert len(chains) == 1
    assert chains[0].artifact.value == VICTIM_ID


def test_parse_chain_targets_empty_when_not_requested():
    assert parse_chain_targets({}).targets == ()
    assert parse_chain_targets({"chain_targets": {"targets": []}}).targets == ()


def test_parse_chain_targets_accepts_header_pair_list():
    doc = _target_doc()
    doc["chain_targets"]["targets"][0]["attacker_headers"] = [
        ["Authorization", "Bearer chain-token"],
        ["X-Tenant", "7"],
    ]
    policy = parse_chain_targets(doc)
    assert policy.targets[0].attacker_headers == (
        ("Authorization", "Bearer chain-token"),
        ("X-Tenant", "7"),
    )


def test_parse_chain_targets_rejects_template_without_placeholder():
    doc = _target_doc()
    doc["chain_targets"]["targets"][0]["breach"]["path_template"] = (
        "/rest/basket/2"
    )
    with pytest.raises(ValueError, match="placeholder"):
        parse_chain_targets(doc)


def test_parse_chain_targets_rejects_missing_control():
    doc = _target_doc()
    del doc["chain_targets"]["targets"][0]["control"]
    with pytest.raises(ValueError, match="control"):
        parse_chain_targets(doc)


def test_parse_chain_targets_rejects_bad_severity():
    doc = _target_doc()
    doc["chain_targets"]["targets"][0]["severity"] = "SPICY"
    with pytest.raises(ValueError, match="severity"):
        parse_chain_targets(doc)
