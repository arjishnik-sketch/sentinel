class IDORWorkflow:

    def run(self,context):

        findings=context["findings"]

        params=findings.get(

            "parameters",

            []

        )

        return {

            "workflow":"IDOR",

            "priority":"HIGH",

            "interesting":params,

            "tests":[

                "Increment numeric IDs",

                "Swap UUIDs",

                "Negative IDs",

                "Null IDs",

                "Random IDs",

                "Horizontal access",

                "Vertical access",

                "Mass assignment"

            ]

        }


if __name__=="__main__":

    w=IDORWorkflow()

    print(

        w.run(

            {

                "findings":{

                    "parameters":[

                        "id",

                        "userid",

                        "tenant"

                    ]

                }

            }

        )

    )
