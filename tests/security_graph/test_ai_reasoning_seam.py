from __future__ import annotations

import json
from unittest.mock import patch

from app.security_graph.ai.advisor import SecurityReasoningAdvisor
from app.security_graph.ai.schema import (
    ReasoningAdvice,
    validate_advice_against_candidates,
)


def test_reasoning_advice_rejects_invalid_confidence() -> None:
    try:
        ReasoningAdvice.from_dict(
            {
                "hypothesis_ids": [],
                "candidate_ids": [],
                "reasoning": "test",
                "suggested_focus": "test",
                "confidence": 2.0,
            }
        )
    except ValueError:
        return

    raise AssertionError("Invalid confidence was accepted")


def test_reasoning_advice_filters_unknown_references() -> None:
    advice = ReasoningAdvice.from_dict(
        {
            "hypothesis_ids": ["h1", "fake-hypothesis"],
            "candidate_ids": ["c1", "fake-candidate"],
            "reasoning": "existing evidence suggests further investigation",
            "suggested_focus": "authorization boundary",
            "confidence": 0.8,
        }
    )

    validated = validate_advice_against_candidates(
        advice,
        valid_hypothesis_ids={"h1"},
        valid_candidate_ids={"c1"},
    )

    assert validated.hypothesis_ids == ("h1",)
    assert validated.candidate_ids == ("c1",)


def test_advisor_is_stateless_and_uses_structured_output() -> None:
    response_body = {
        "message": {
            "content": json.dumps(
                {
                    "choice": 0,
                    "reasoning": "strongest evidence-backed value",
                    "confidence": 0.85,
                }
            )
        }
    }

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps(response_body).encode("utf-8")

    with patch(
        "app.security_graph.ai.advisor.urllib.request.urlopen",
        return_value=FakeResponse(),
    ) as mocked:

        advisor = SecurityReasoningAdvisor(
            url="http://example.test",
            model="qwen3:4b",
            timeout=5,
        )

        result = advisor.advise(
            context={
                "target": "example.test",
                "observations": [],
            },
            candidates=[
                {
                    "id": "c1",
                    "hypothesis_id": "h1",
                    "action": "authorization_http_check",
                    "capability_id": "authorization.candidate_check",
                }
            ],
        )

    # The advisor selects by index; Sentinel maps it back to the real id.
    assert result.candidate_ids == ("c1",)
    assert result.hypothesis_ids == ()
    assert result.confidence == 0.85

    request = mocked.call_args.args[0]

    payload = json.loads(request.data.decode("utf-8"))

    assert payload["model"] == "qwen3:4b"
    assert payload["stream"] is False
    assert payload["format"] == "json"
    assert payload["options"]["num_ctx"] == 4096


def test_advisor_does_not_mutate_supplied_inputs() -> None:
    context = {
        "target": "example.test",
        "observations": [],
    }

    candidates = [
        {
            "id": "c1",
            "hypothesis_id": "h1",
        }
    ]

    original_context = json.loads(json.dumps(context))
    original_candidates = json.loads(json.dumps(candidates))

    response_body = {
        "message": {
            "content": json.dumps(
                {
                    "choice": 0,
                    "reasoning": "test",
                    "confidence": 0.5,
                }
            )
        }
    }

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps(response_body).encode("utf-8")

    with patch(
        "app.security_graph.ai.advisor.urllib.request.urlopen",
        return_value=FakeResponse(),
    ):
        SecurityReasoningAdvisor(
            url="http://example.test",
            model="qwen3:4b",
            timeout=5,
        ).advise(
            context=context,
            candidates=candidates,
        )

    assert context == original_context
    assert candidates == original_candidates
