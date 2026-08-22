"""Stateless Ollama-backed reasoning advisor for Sentinel."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any

from app.config import (
    AI_ADVISORY_NUM_PREDICT,
    AI_ADVISORY_TIMEOUT,
    OLLAMA_MODEL,
    OLLAMA_URL,
)

from .prompts import SYSTEM_PROMPT, USER_TEMPLATE
from .schema import ReasoningAdvice

logger = logging.getLogger(__name__)


def _format_candidate_menu(candidates: list[dict[str, Any]]) -> str:
    """Render candidates as a compact, numbered menu for the advisor.

    The advisor selects by the leading number, so ids never need to be
    echoed back. Each line stays short: id, action, capability, and the
    single most salient rationale line if present.
    """
    lines = []
    for index, candidate in enumerate(candidates):
        rationale = candidate.get("rationale") or []
        why = rationale[0] if rationale else ""
        lines.append(
            f"{index}: {candidate.get('id')} "
            f"| {candidate.get('action')} "
            f"| {candidate.get('capability_id')}"
            + (f" | {why}" if why else "")
        )
    return "\n".join(lines)


class SecurityReasoningAdvisor:
    """
    Bounded, stateless LLM advisor.

    This class does not execute experiments and does not mutate the
    SecurityGraph. Its output is untrusted advisory data.
    """

    def __init__(
        self,
        *,
        url: str | None = None,
        model: str | None = None,
        timeout: int | None = None,
    ) -> None:
        self.url = (url or OLLAMA_URL).rstrip("/")
        self.model = model or OLLAMA_MODEL
        self.timeout = timeout or AI_ADVISORY_TIMEOUT

    def advise(
        self,
        *,
        context: dict[str, Any],
        candidates: list[dict[str, Any]],
    ) -> ReasoningAdvice:
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": USER_TEMPLATE.format(
                        context=json.dumps(
                            context,
                            sort_keys=True,
                            default=str,
                        ),
                        candidates=_format_candidate_menu(
                            candidates
                        ),
                    ),
                },
            ],
            "stream": False,
            "format": "json",
            # qwen3 is a reasoning model; disabling the hidden thinking
            # phase keeps this bounded tiebreak fast and predictable.
            "think": False,
            "options": {
                "num_ctx": 4096,
                "num_predict": AI_ADVISORY_NUM_PREDICT,
            },
        }

        request = urllib.request.Request(
            f"{self.url}/api/chat",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout,
            ) as response:
                body = response.read().decode("utf-8")

        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(
                "utf-8",
                errors="replace",
            )
            raise RuntimeError(
                f"Ollama reasoning request failed with HTTP "
                f"{exc.code}: {detail[:1000]}"
            ) from exc

        except (urllib.error.URLError, TimeoutError) as exc:
            raise RuntimeError(
                f"Ollama reasoning request failed: {exc}"
            ) from exc

        try:
            envelope = json.loads(body)
            content = envelope["message"]["content"]
            result = json.loads(content)
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                "Ollama returned an invalid structured reasoning response"
            ) from exc

        # The advisor selects by index into the supplied candidate list.
        # Sentinel maps that number back to its own candidate id, so the
        # model can neither invent nor mis-spell an id. An out-of-range or
        # missing choice yields no preference (empty candidate_ids), which
        # the deterministic layer treats as "no advisory signal".
        chosen_ids: list[str] = []
        choice = result.get("choice")
        try:
            choice_index = int(choice)
        except (TypeError, ValueError):
            choice_index = None

        if (
            choice_index is not None
            and 0 <= choice_index < len(candidates)
        ):
            chosen_id = candidates[choice_index].get("id")
            if isinstance(chosen_id, str) and chosen_id:
                chosen_ids = [chosen_id]

        # Clamp confidence before schema validation so a slightly
        # out-of-range value degrades gracefully instead of discarding an
        # otherwise usable choice.
        try:
            confidence = float(result.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        confidence = min(1.0, max(0.0, confidence))

        return ReasoningAdvice.from_dict(
            {
                "candidate_ids": chosen_ids,
                "reasoning": str(result.get("reasoning", "")),
                "confidence": confidence,
            }
        )
