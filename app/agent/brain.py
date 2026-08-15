from rich.console import Console
from rich.table import Table

from .memory import AgentMemory
from .decision import Decision
from .planner import AgentPlanner

console = Console()


class AgentBrain:

    def __init__(self):

        self.memory = AgentMemory()

    def think(self, state):

        planner = AgentPlanner()

        state.top_skills = planner.choose(state)

        table = Table(title="Agent Brain")

        table.add_column("Property")

        table.add_column("Value")

        table.add_row("Target", state.target)

        table.add_row("Evidence", str(len(state.evidence)))

        table.add_row("Skills", str(len(state.skills)))

        table.add_row("Top Skills", str(len(state.top_skills)))

        console.print(table)

        if not state.top_skills:

            from app.knowledge.reasoner import KnowledgeReasoner

            reasoner = KnowledgeReasoner()

            best = state.top_skills[0]

            procedure = reasoner.explain({

                "title": best.title,

                "objective": best.objective,

                "tools": best.tools,

                "prerequisites": best.prerequisites

            })

            decision = Decision(

                title=procedure["goal"],

                reason=f"Selected '{best.title}' as highest priority.",

                confidence=min(int(best.priority),100),

                action=procedure["steps"][0] if procedure["steps"] else "Manual Review"

            )

        else:

            best = state.top_skills[0]

            decision = Decision(

                title=best.title,

                reason="Highest ranked security skill.",

                confidence=int(best.priority),

                action="Generate investigation procedure"

            )

        state.current_goal = decision.title

        state.next_action = decision.action

        state.confidence = decision.confidence

        state.decisions.append(decision)

        self.memory.remember(decision)

        return decision
    
    