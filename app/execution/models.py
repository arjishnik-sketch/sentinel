from dataclasses import dataclass, field


@dataclass
class Command:

    tool: str

    command: str

    description: str = ""


@dataclass
class ExecutionStep:

    title: str

    commands: list[Command] = field(default_factory=list)

    notes: str = ""


@dataclass
class ExecutionPlan:

    skill: str

    confidence: int

    target: str

    steps: list[ExecutionStep] = field(default_factory=list)

    evidence: list[str] = field(default_factory=list)