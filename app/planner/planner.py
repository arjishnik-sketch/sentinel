def plan(task):

    task = task.lower()

    if task.startswith("bughunt "):

        domain = task.split(maxsplit=1)[1]

        return {
            "domain": domain,
            "steps":[
                "Subfinder",
                "Httpx",
                "Katana",
                "Waybackurls",
                "GAU",
                "AI Analysis"
            ],
            "eta":"2-5 minutes"
        }

    return None
