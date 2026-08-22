"""Schemas for Sentinel's bounded AI reasoning seam."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ReasoningAdvice:
    """
    Untrusted advisory output produced by the LLM.

    The advisor may reference existing Sentinel objects, but it does not
    create executable requests, evidence, findings, or authorization claims.
    """

    hypothesis_ids: tuple[str, ...] = field(default_factory=tuple)
    candidate_ids: tuple[str, ...] = field(default_factory=tuple)
    reasoning: str = ""
    suggested_focus: str = ""
    confidence: float = 0.0

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReasoningAdvice":
        if not isinstance(data, dict):
            raise ValueError("AI response must be a JSON object")

        hypothesis_ids = data.get("hypothesis_ids", [])
        candidate_ids = data.get("candidate_ids", [])
        reasoning = data.get("reasoning", "")
        suggested_focus = data.get("suggested_focus", "")
        confidence = data.get("confidence", 0.0)

        if not isinstance(hypothesis_ids, list):
            raise ValueError("hypothesis_ids must be a list")

        if not isinstance(candidate_ids, list):
            raise ValueError("candidate_ids must be a list")

        if not all(isinstance(value, str) for value in hypothesis_ids):
            raise ValueError("hypothesis_ids must contain strings")

        if not all(isinstance(value, str) for value in candidate_ids):
            raise ValueError("candidate_ids must contain strings")

        if not isinstance(reasoning, str):
            raise ValueError("reasoning must be a string")

        if not isinstance(suggested_focus, str):
            raise ValueError("suggested_focus must be a string")

        try:
            confidence = float(confidence)
        except (TypeError, ValueError) as exc:
            raise ValueError("confidence must be numeric") from exc

        if not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")

        return cls(
            hypothesis_ids=tuple(hypothesis_ids),
            candidate_ids=tuple(candidate_ids),
            reasoning=reasoning[:4000],
            suggested_focus=suggested_focus[:1000],
            confidence=confidence,
        )


def validate_advice_against_candidates(
    advice: ReasoningAdvice,
    *,
    valid_hypothesis_ids: set[str],
    valid_candidate_ids: set[str],
) -> ReasoningAdvice:
    """
    Deterministically constrain AI references to objects Sentinel already knows.

    Invalid references are discarded rather than trusted.
    """

    return ReasoningAdvice(
        hypothesis_ids=tuple(
            value
            for value in advice.hypothesis_ids
            if value in valid_hypothesis_ids
        ),
        candidate_ids=tuple(
            value
            for value in advice.candidate_ids
            if value in valid_candidate_ids
        ),
        reasoning=advice.reasoning,
        suggested_focus=advice.suggested_focus,
        confidence=advice.confidence,
    )
