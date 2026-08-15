from dataclasses import dataclass, field


@dataclass
class Skill:

    id: int = 0

    title: str = ""

    category: str = ""

    objective: str = ""

    path: str = ""

    score: int = 0

    automation: int = 0

    tools: list = field(default_factory=list)

    tags: list = field(default_factory=list)

    prerequisites: list = field(default_factory=list)

    methodology: list = field(default_factory=list)

    references: list = field(default_factory=list)

    priority: float = 0

    confidence: float = 0


@dataclass
class SkillList:

    evidence: list = field(default_factory=list)

    expanded: list = field(default_factory=list)

    skills: list = field(default_factory=list)

    procedures: list = field(default_factory=list)