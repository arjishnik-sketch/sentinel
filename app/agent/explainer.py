class DecisionExplainer:

    def explain(self, skill):

        return [

            f"Matched title: {skill.title}",

            f"Priority Score: {skill.priority:.0f}",

            f"Automation: {skill.automation}",

            f"Tools: {', '.join(skill.tools)}"

        ]