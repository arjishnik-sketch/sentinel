from dataclasses import dataclass, field


@dataclass
class AgentState:

    target: str = ""

    recon: dict = field(default_factory=dict)

    evidence: list = field(default_factory=list)

    skills: list = field(default_factory=list)

    top_skills: list = field(default_factory=list)

    procedures: list = field(default_factory=list)

    decisions: list = field(default_factory=list)

    findings: list = field(default_factory=list)

    confidence: int = 0

    current_goal: str = ""

    next_action: str = ""