from .models import (
    Command,
    ExecutionPlan,
    ExecutionStep
)

from .commands import CommandBuilder


class SkillPlanner:

    def __init__(self):

        self.builder = CommandBuilder()

    def plan(

        self,

        skill,

        target,

        confidence=80

    ):

        step = ExecutionStep(

            title="Execute Skill"

        )

        for cmd in skill["commands"]:

            step.commands.append(

                Command(

                    tool="shell",

                    command=self.builder.build(

                        cmd,

                        target

                    )

                )

            )

        return ExecutionPlan(

            skill=skill["title"],

            confidence=confidence,

            target=target,

            steps=[step]

        )