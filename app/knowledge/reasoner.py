import json

from app.ai import SentinelAI


class KnowledgeReasoner:

    def __init__(self):

        self.ai = SentinelAI()

    def explain(self, skill):

        prompt = f"""
        
        You are a senior bug bounty hunter.

        Your job is to teach another penetration tester how to perform this security assessment.

        Skill

        Title:
        {skill["title"]}

        Objective:
        {skill["objective"]}

        Tools:
        {skill["tools"]}

        Prerequisites:
        {skill["prerequisites"]}

        Return ONLY valid JSON.

        {{
        "goal":"",
        "steps":[
            "Step 1",
            "Step 2",
            "Step 3"
        ],
        "expected_result":"",
        "risk":"Low|Medium|High",
        "next_tests":[]
        }}

        Rules

        - Infer the testing procedure.
        - Do NOT copy markdown.
        - Produce practical testing steps.
        - Produce 3-8 ordered steps.
        - next_tests should contain logical follow-up tests.
        """



        reply = self.ai.ask(prompt)

        try:

            return json.loads(reply)

        except Exception:

            return {

                "goal":"",

                "steps":[],

                "expected_result":"",

                "risk":"Unknown"

            }