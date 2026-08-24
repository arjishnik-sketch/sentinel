"""
PURE artifact extraction: read typed values out of a proven finding's OWN
recorded evidence, never inventing them.

The first honest chain is **SQLi ⇒ IDOR/BOLA**. A confirmed SQL injection's
VALIDATED arm is, by construction, the boolean-tautology probe whose response
dumped a superset of rows — exactly where a real injection leaks *other*
objects' identifiers. Because every HTTP probe records a bounded
``response_body_text`` prefix into its evidence (see
:mod:`app.security_graph.execution.http`), the leaked identifiers are already
sitting in the graph even though the injection judge itself only ever read the
``(status, length)`` fingerprint. This module reads them back out.

Extraction is a pure function of graph state: it follows
``finding → VALIDATED judgment → TRUE-arm experiment → HTTP evidence →
response_body_text`` and harvests id-shaped values. It performs no network I/O,
no scoring, and no mutation. If the leaked body contains no identifier, no
artifact is produced (never a false lead).
"""

from __future__ import annotations

import json
import re

from ..graph import SecurityGraph
from ..models import SecurityFinding
from .chain_finding import ChainArtifact


# Keys whose name marks their value as an object identifier. Matched
# case-insensitively; both ``id`` and any ``*_id`` / ``*Id`` style key count.
def _is_id_key(key: str) -> bool:
    lowered = key.lower()
    return lowered == "id" or lowered.endswith("id") or lowered.endswith("_id")


# Regex fallback for non-JSON bodies (HTML/text): "...id": <value> or id=<value>.
_ID_TEXT_RE = re.compile(
    r'["\']?(\w*id)["\']?\s*[:=]\s*["\']?([A-Za-z0-9][A-Za-z0-9\-]{0,63})',
    re.IGNORECASE,
)

_MAX_ARTIFACTS = 64


def _validated_judgment(graph: SecurityGraph, *, hypothesis_id: str, contradiction_kind: str):
    """The VALIDATED judgment for this hypothesis/class, or None."""
    for judgment in graph.validation_judgments.values():
        if (
            judgment.hypothesis_id == hypothesis_id
            and judgment.status == "VALIDATED"
            and judgment.contradiction_kind == contradiction_kind
        ):
            return judgment
    return None


def _true_arm_body_text(graph: SecurityGraph, judgment) -> tuple[str, str] | None:
    """
    (response_body_text, evidence_id) of the VALIDATED arm's HTTP probe, or None.

    ``judgment.experiment_id`` is, for the injection judge, exactly the TRUE-arm
    (boolean-tautology) experiment — the arm whose response reproduced/expanded
    the leaked result set.
    """
    experiment = graph.experiments.get(judgment.experiment_id)
    if experiment is None:
        return None
    for evidence_id in experiment.evidence_ids:
        evidence = graph.evidence.get(evidence_id)
        if evidence is None:
            continue
        data = evidence.data
        if isinstance(data, dict) and data.get("mode") == "http":
            text = data.get("response_body_text")
            if isinstance(text, str) and text:
                return text, evidence.id
    return None


def _walk_json_ids(node, *, path: str, out: list[tuple[str, str]]) -> None:
    """Collect (value, locator) for every id-keyed scalar in a decoded body."""
    if isinstance(node, dict):
        for key, value in node.items():
            child_path = f"{path}.{key}" if path else str(key)
            if _is_id_key(str(key)) and isinstance(value, (str, int)) and not isinstance(value, bool):
                out.append((str(value), child_path))
            else:
                _walk_json_ids(value, path=child_path, out=out)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _walk_json_ids(value, path=f"{path}[{index}]", out=out)


def _harvest_ids(body_text: str) -> list[tuple[str, str]]:
    """Extract id-shaped (value, locator) pairs from a leaked body, JSON-first."""
    collected: list[tuple[str, str]] = []
    try:
        decoded = json.loads(body_text)
    except (ValueError, TypeError):
        decoded = None

    if decoded is not None:
        _walk_json_ids(decoded, path="", out=collected)

    if not collected:
        # Non-JSON (HTML/text) body: fall back to a bounded id-pattern scan.
        for match in _ID_TEXT_RE.finditer(body_text):
            collected.append((match.group(2), match.group(1).lower()))

    # De-duplicate on value, preserve first-seen order, bound the count.
    seen: set[str] = set()
    unique: list[tuple[str, str]] = []
    for value, locator in collected:
        if value and value not in seen:
            seen.add(value)
            unique.append((value, locator))
        if len(unique) >= _MAX_ARTIFACTS:
            break
    return unique


def _extract_injection_object_ids(
    graph: SecurityGraph,
    finding: SecurityFinding,
) -> list[ChainArtifact]:
    judgment = _validated_judgment(
        graph, hypothesis_id=finding.hypothesis_id, contradiction_kind="injection"
    )
    if judgment is None:
        return []
    body = _true_arm_body_text(graph, judgment)
    if body is None:
        return []
    body_text, evidence_id = body
    return [
        ChainArtifact(
            kind="leaked_object_id",
            value=value,
            source_finding_id=finding.id,
            source_kind="injection",
            evidence_id=evidence_id,
            locator=locator,
        )
        for value, locator in _harvest_ids(body_text)
    ]


# Dispatch table: which extractor(s) apply to a source finding of a given kind.
_EXTRACTORS = {
    "injection": _extract_injection_object_ids,
}


def extract_artifacts(
    graph: SecurityGraph,
    finding: SecurityFinding,
) -> list[ChainArtifact]:
    """
    Extract every typed artifact carried by a proven finding's real evidence.

    Pure: reads only graph state, invents nothing. Returns an empty list for a
    finding kind with no registered extractor, or when the recorded evidence
    contains no artifact of the relevant type.
    """
    extractor = _EXTRACTORS.get(finding.kind)
    if extractor is None:
        return []
    return extractor(graph, finding)
