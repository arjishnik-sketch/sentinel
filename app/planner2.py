class Planner:

    def plan(self, findings):

        plan=[]

        if findings["graphql"]:
            plan.append("graphql")

        if findings["parameters"]:
            plan.append("idor")

        if findings["uploads"]:
            plan.append("upload")

        if findings["logins"]:
            plan.append("auth")

        if findings["javascript"]:
            plan.append("javascript")

        if findings["apis"]:
            plan.append("api")

        return plan


if __name__=="__main__":

    p=Planner()

    print(

        p.plan(

            {

                "graphql":[1],

                "parameters":[1],

                "uploads":[],

                "logins":[1],

                "javascript":[1],

                "apis":[1]

            }

        )

    )
