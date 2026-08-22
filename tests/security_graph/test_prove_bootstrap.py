"""
Network-free proof that the prove-chain fires end to end.

Closing the bootstrap gap means: an operator-declared access policy, seeded
into the graph, drives a real autonomous investigation cycle in which the
deterministic judge — not an HTTP status, not the seeder — decides the
outcome. A canned executor stands in for the live target so the proof is
deterministic and offline.

The three cases pin the epistemic contract:

  * deny policy + observed 200  -> VALIDATED -> CONFIRMED finding
        (a reproduced contradiction: target allows what policy denies)
  * deny policy + observed 401  -> DISPROVED -> no finding
        (target honours the policy; Sentinel refuses to invent a finding)
  * allow policy + observed 200 -> DISPROVED -> no finding
        (an allow that is honoured is not a violation)

Together they show a 200 is never a verdict by itself, and that seeding
only *routes a suspicion* — it can never manufacture a finding.
"""

from app.security_graph.execution import ExecutorRegistry, ExperimentExecutor
from app.security_graph.graph import SecurityGraph
from app.security_graph.models import Evidence, ExecutionResult
from app.security_graph.orchestration.cycle import run_investigation_cycle
from app.security_graph.policy import parse_access_policy, seed_access_policy


TARGET_BASE = "http://127.0.0.1:3000"


class _CannedExecutor(ExperimentExecutor):
    """Return a fixed HTTP status for every validation probe."""

    kind = "authorization_http_check"

    def __init__(self, status_code: int):
        self._status_code = status_code

    def execute(self, experiment) -> ExecutionResult:
        evidence = Evidence(
            id=f"ev:probe:{experiment.id}",
            source="http_response",
            data={
                "mode": "http",
                "status_code": self._status_code,
                "experiment_id": experiment.id,
                "endpoint_id": None,
            },
            confidence=1.0,
        )
        return ExecutionResult(
            experiment_id=experiment.id,
            status="COMPLETED",
            evidence=(evidence,),
            metadata=(("status_code", str(self._status_code)),),
        )


def _policy(decision: str, path: str = "/api/Feedbacks") -> object:
    return parse_access_policy(
        {
            "principals": [{"name": "anonymous", "kind": "anonymous"}],
            "rules": [
                {
                    "principal": "anonymous",
                    "method": "GET",
                    "path": path,
                    "action": "read",
                    "decision": decision,
                }
            ],
        }
    )


def _seed(decision: str) -> tuple[SecurityGraph, str]:
    graph = SecurityGraph()
    seeded = seed_access_policy(
        graph,
        _policy(decision),
        target_base=TARGET_BASE,
    )
    assert len(seeded) == 1
    return graph, seeded[0]


def _run_one_decisive_cycle(graph: SecurityGraph, status_code: int):
    registry = ExecutorRegistry()
    registry.register(_CannedExecutor(status_code))

    # The seeded policy hypothesis is the sole OPEN hypothesis, so the very
    # first cycle selects policy validation, probes, and judges.
    result = run_investigation_cycle(graph, registry)
    assert result is not None
    assert result.judgment is not None
    return result


def test_seed_does_not_manufacture_an_observation_or_finding():
    graph, hyp_id = _seed("deny")

    # Seeding creates the hypothesis and the explicit policy edge, but no
    # authorization observation and no finding: nothing has been probed.
    assert graph.hypotheses[hyp_id].status == "OPEN"
    assert graph.hypotheses[hyp_id].kind == "authorization_policy_violation"
    assert graph.authorization_observations == {}
    assert graph.findings == {}

    # The synthetic declaration evidence must never be an HTTP observation.
    for evidence in graph.evidence.values():
        assert evidence.data.get("mode") != "http"


def test_deny_policy_with_observed_allow_confirms():
    graph, hyp_id = _seed("deny")

    result = _run_one_decisive_cycle(graph, status_code=200)

    assert result.judgment.status == "VALIDATED"
    assert graph.hypotheses[hyp_id].status == "CONFIRMED"

    findings = list(graph.findings.values())
    assert len(findings) == 1
    finding = findings[0]
    # A finding is only ever derived from a CONFIRMED hypothesis, so its
    # existence is itself the proof of adjudication. Its own lifecycle
    # status is OPEN — an open, unremediated finding to report.
    assert finding.kind == "authorization_policy_violation"
    assert finding.hypothesis_id == hyp_id
    assert finding.severity == "HIGH"
    assert finding.status == "OPEN"
    assert "Broken access control" in finding.title


def test_deny_policy_with_observed_deny_disproves_and_produces_no_finding():
    graph, hyp_id = _seed("deny")

    result = _run_one_decisive_cycle(graph, status_code=401)

    assert result.judgment.status == "DISPROVED"
    assert graph.hypotheses[hyp_id].status == "DISPROVED"
    assert graph.findings == {}


def test_allow_policy_with_observed_allow_disproves_and_produces_no_finding():
    graph, hyp_id = _seed("allow")

    result = _run_one_decisive_cycle(graph, status_code=200)

    assert result.judgment.status == "DISPROVED"
    assert graph.hypotheses[hyp_id].status == "DISPROVED"
    assert graph.findings == {}
