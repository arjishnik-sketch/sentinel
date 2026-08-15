from .recon_engine import ReconEngine
from .planner2 import Planner
from .workflow_runner import WorkflowRunner
from .findings import Findings
from .dashboard import Dashboard
from .planner.rag import RAGPlanner

from .agent.state import AgentState
from .agent.brain import AgentBrain

from .knowledge.compiler import KnowledgeCompiler
from .knowledge.reasoner import KnowledgeReasoner
from .knowledge.pipeline import KnowledgePipeline

class SentinelCore:

    def __init__(self):

        self.engine = ReconEngine()

        self.planner = Planner()

        self.runner = WorkflowRunner()

        self.findings = Findings()

        self.dashboard = Dashboard()
        
        self.rag = RAGPlanner()
        
        self.compiler = KnowledgeCompiler()

        self.reasoner = KnowledgeReasoner()

        self.brain = AgentBrain()
        
        self.pipeline = KnowledgePipeline()

    def hunt(self, target):

        self.findings = Findings()

        recon = self.engine.run_pipeline(target)

        knowledge = self.rag.analyze(recon)

        print("\n========== DEBUG ==========")

        print("Evidence:")
        print(knowledge["evidence"])

        print()

        print("Skill Categories:")
        print(list(knowledge["skills"].keys()))

        print()

        for category, skills in knowledge["skills"].items():
            print(category, len(skills))

        print("===========================\n")

        state = AgentState()

        state.target = target

        state.recon = recon

        state.evidence = knowledge["evidence"]

        knowledge_data = self.pipeline.run(
            state.evidence
        )

        state.skills = compiled

        state.procedures = procedures

        decision = self.brain.think(state)

        console.print()

        console.print(

            Panel.fit(

    f"""
    [bold cyan]Current Goal[/bold cyan]

    {decision.title}

    [bold green]Reason[/bold green]

    {decision.reason}

    [bold yellow]Next Action[/bold yellow]

    {decision.action}

    Confidence

    {decision.confidence}%
    """,

    title="🧠 Sentinel Decision"

            )

        )

        skill_context = self.build_skill_context(
            knowledge
        )

        analysis = self.engine.analyze(

            recon,

            skill_context

        )

        self.engine.save(

            recon,

            analysis["summary"]

        )

        report = self.engine.markdown_report(

            recon,

            analysis

        )

        result = {

            "target": target,

            "report": str(report),

            "analysis": analysis,

            "recon": recon

        }

        findings = result["analysis"]["findings"]

        plan = self.planner.plan(findings)

        workflow_results = self.runner.execute(

            plan,

            {

                "findings": findings

            }

        )

        for w in workflow_results:

            self.findings.add(

                w["workflow"],

                "Info",

                w,

                w["workflow"]

            )

        self.dashboard.show(

            target,

            self.findings.all(),

            plan

        )

        return {

            "scan": result,

            "plan": plan,

            "workflow_results": workflow_results,

            "findings": self.findings.all()

        }

    def build_skill_context(self, knowledge):

        lines = []

        for category, skills in knowledge["skills"].items():

            lines.append(f"\n[{category}]")

            for s in skills:

                lines.append(
                    f"- {s['title']}"
                )

        return "\n".join(lines)


if __name__=="__main__":

    s=SentinelCore()

    s.hunt("meta.com")
