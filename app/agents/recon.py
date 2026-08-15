from .shell import run

def recon(domain):
    print("\\n[*] Running subfinder...")
    subs = run(f"subfinder -silent -d {domain}")

    print("[*] Running httpx...")
    alive = run(f"printf '%s' '{subs}' | httpx -silent")

    print("[*] Running katana...")
    urls = run(f"printf '%s' '{alive}' | katana -silent")

    graphql = []
    swagger = []
    login = []
    admin = []
    api = []

    for u in urls.splitlines():
        l = u.lower()

        if "/graphql" in l:
            graphql.append(u)

        if "swagger" in l or "api-doc" in l:
            swagger.append(u)

        if "/login" in l or "/signin" in l:
            login.append(u)

        if "/admin" in l:
            admin.append(u)

        if "/api/" in l:
            api.append(u)

    return {
        "domain": domain,
        "subdomains": sorted(set(filter(None, subs.splitlines()))),
        "alive": sorted(set(filter(None, alive.splitlines()))),
        "graphql": sorted(set(graphql)),
        "swagger": sorted(set(swagger)),
        "login": sorted(set(login)),
        "admin": sorted(set(admin)),
        "api": sorted(set(api))
    }
