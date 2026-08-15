from dataclasses import dataclass


@dataclass
class Decision:

    title: str

    reason: str

    confidence: int

    action: str

    expected_gain: str = "Medium"