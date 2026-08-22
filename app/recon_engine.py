from datetime import datetime, UTC
import json
from pathlib import Path

from .ai import SentinelAI
from .memory import Memory
from .pipeline import Pipeline

from .plugins.subfinder import Subfinder
from .plugins.httpx import Httpx
from .plugins.katana import Katana
import re


class ReconEngine:

    def __init__(self):

        self.ai = SentinelAI()

        self.memory = Memory()

        self.pipeline = (
            Pipeline()
            .add(Subfinder())
            .add(Httpx())
            .add(Katana())
        )

    @staticmethod
    def normalize(target: str):

        target = target.strip()

        if "://" in target:
            scheme, remainder = target.split("://", 1)
            remainder = remainder.split("/", 1)[0]
            return f"{scheme.lower()}://{remainder.lower()}"

        return target.split("/", 1)[0].lower()

    @staticmethod
    def timestamp():

        return datetime.now(UTC).isoformat()

    def run_direct_target(self, target: str):

        target = self.normalize(target)

        import time

        start = time.time()

        httpx = Httpx()
        katana = Katana()

        httpx_result = httpx.run(target)

        if not httpx_result["success"]:
            return {
                "success": False,
                "duration": round(
                    time.time() - start,
                    2,
                ),
                "steps": 1,
                "results": [httpx_result],
            }

        katana_result = katana.run(
            httpx_result["results"]
        )

        return {
            "success": katana_result["success"],
            "duration": round(
                time.time() - start,
                2,
            ),
            "steps": 2,
            "results": [
                httpx_result,
                katana_result,
            ],
        }

    def run_pipeline(self, target: str):

        target = self.normalize(target)

        is_direct_target = (
            "://" in target
            or ":" in target.split("/", 1)[0]
        )

        if is_direct_target:
            result = self.run_direct_target(target)
        else:
            result = self.pipeline.run(target)

        recon = {
            "target": target,
            "timestamp": self.timestamp(),
            "pipeline": result,
            "subdomains": [],
            "alive": [],
            "crawl": []
        }

        for step in result["results"]:

            tool = step["tool"]

            if tool == "subfinder":
                recon["subdomains"] = step["results"]

            elif tool == "httpx":
                recon["alive"] = step["results"]

            elif tool == "katana":
                recon["crawl"] = step["results"]

        # Fallback: when external recon binaries are unavailable, or the
        # tool pipeline discovered no crawlable surface, use the built-in
        # dependency-free crawler so discovery still works in any
        # environment. This keeps Sentinel deployable without a
        # pre-provisioned tool chain.
        if not recon["crawl"]:

            from .security_graph.recon.crawler import crawl_target

            fallback = crawl_target(target)

            if fallback["crawl"]:

                if not recon["alive"]:
                    recon["alive"] = fallback["alive"]

                recon["crawl"] = fallback["crawl"]

                recon["source"] = "builtin_crawler"

        return recon


    def statistics(self, recon):

        return {

            "subdomains": len(recon["subdomains"]),

            "alive": len(recon["alive"]),

            "crawl": len(recon["crawl"])

        }


    def save(self, recon, summary):

        self.memory.save_scan(

            recon["target"],

            summary,

            recon

        )
        
    def extract(self, recon):

        endpoints = recon["crawl"]

        findings = {
            "logins": [],
            "admins": [],
            "apis": [],
            "graphql": [],
            "swagger": [],
            "uploads": [],
            "javascript": [],
            "parameters": set()
        }

        login_words = [
            "login",
            "signin",
            "auth",
            "oauth",
            "account"
        ]

        admin_words = [
            "admin",
            "dashboard",
            "manage",
            "panel",
            "console"
        ]

        api_words = [
            "/api/",
            "/v1/",
            "/v2/",
            "/v3/"
        ]

        swagger_words = [
            "swagger",
            "openapi",
            "api-docs"
        ]

        upload_words = [
            "upload",
            "file",
            "image",
            "avatar",
            "media"
        ]

        for url in endpoints:

            lower = url.lower()

            if any(x in lower for x in login_words):
                findings["logins"].append(url)

            if any(x in lower for x in admin_words):
                findings["admins"].append(url)

            if any(x in lower for x in api_words):
                findings["apis"].append(url)

            if "graphql" in lower:
                findings["graphql"].append(url)

            if any(x in lower for x in swagger_words):
                findings["swagger"].append(url)

            if any(x in lower for x in upload_words):
                findings["uploads"].append(url)

            if lower.endswith(".js"):
                findings["javascript"].append(url)

            if "?" in url:

                query = url.split("?", 1)[1]

                for pair in query.split("&"):

                    if "=" in pair:

                        findings["parameters"].add(
                            pair.split("=")[0]
                        )

        findings["parameters"] = sorted(
            findings["parameters"]
        )


        # Generic JS-derived API route discovery.
        # Only explicit route-like references are promoted; JS assets themselves are not APIs.
        for js_url in findings.get("javascript", []):
            if not isinstance(js_url, str):
                continue
            try:
                import urllib.request
                body = urllib.request.urlopen(js_url, timeout=5).read(2_000_000).decode("utf-8", "ignore")
            except Exception:
                continue
            route_patterns = (
                r"[\"']((?:https?://[^\"']+)?/api/[A-Za-z0-9_./?=&-]+)[\"']",
                r"[\"']((?:https?://[^\"']+)?/graphql(?:/[A-Za-z0-9_./?=&-]*)?)[\"']",
                r"[\"']((?:https?://[^\"']+)?/rest/[A-Za-z0-9_./?=&-]+)[\"']",
            )
            for pattern in route_patterns:
                for route in re.findall(pattern, body):
                    if route.startswith("http://") or route.startswith("https://"):
                        findings["apis"].append(route)
                    else:
                        from urllib.parse import urljoin
                        findings["apis"].append(urljoin(js_url, route))
        findings["apis"] = sorted(set(findings["apis"]))
        return findings


    def overview(self, recon, findings):

        return {

            "target": recon["target"],

            "subdomains": len(recon["subdomains"]),

            "alive": len(recon["alive"]),

            "crawl": len(recon["crawl"]),

            "login_pages": len(findings["logins"]),

            "admin_pages": len(findings["admins"]),

            "api_endpoints": len(findings["apis"]),

            "graphql": len(findings["graphql"]),

            "swagger": len(findings["swagger"]),

            "uploads": len(findings["uploads"]),

            "javascript": len(findings["javascript"]),

            "parameters": len(findings["parameters"])

        }
        
    def ai_analysis(self, recon, findings, skill_context=""):

        overview = self.overview(recon, findings)

        prompt = f"""
            You are a senior Web Application Security Consultant and Bug Bounty Hunter.

            Your task is to analyze ONLY the evidence provided below.

            DO NOT invent hosts.
            DO NOT invent endpoints.
            DO NOT claim vulnerabilities exist.
            If something is missing, say "Not observed."

            ========================
            TARGET
            ========================

            {overview["target"]}

            ========================
            STATISTICS
            ========================

            Subdomains : {overview["subdomains"]}
            Alive Hosts : {overview["alive"]}
            Crawled URLs : {overview["crawl"]}

            Login Pages : {overview["login_pages"]}
            Admin Pages : {overview["admin_pages"]}
            API Endpoints : {overview["api_endpoints"]}
            GraphQL : {overview["graphql"]}
            Swagger : {overview["swagger"]}
            Upload Endpoints : {overview["uploads"]}
            JavaScript Files : {overview["javascript"]}
            Parameters : {overview["parameters"]}

            ========================
            LOGIN PAGES
            ========================

            {json.dumps(findings["logins"], indent=2)}

            ========================
            ADMIN PAGES
            ========================

            {json.dumps(findings["admins"], indent=2)}

            ========================
            GRAPHQL
            ========================

            {json.dumps(findings["graphql"], indent=2)}

            ========================
            SWAGGER
            ========================

            {json.dumps(findings["swagger"], indent=2)}

            ========================
            UPLOADS
            ========================

            {json.dumps(findings["uploads"], indent=2)}

            ========================
            PARAMETERS
            ========================

            {json.dumps(findings["parameters"], indent=2)}

            ========================
            RELEVANT SECURITY SKILLS
            ========================

            {skill_context}

            ========================
            YOUR TASK
            ========================

            Produce the following sections.

            # Executive Summary

            # High Priority Manual Tests

            # Interesting Endpoints

            # Authentication Review

            # Authorization (IDOR/BOLA) Ideas

            # File Upload Review

            # GraphQL Review

            # API Review

            # Suggested nuclei Commands

            # Suggested ffuf Commands

            # Suggested curl Commands

            # Confidence

            Remember:

            Only use supplied evidence.
            Never fabricate findings.
            """

        return self.ai.ask(prompt)

    def analyze(self, recon, skill_context=""):

        findings = self.extract(recon)

        summary = self.ai_analysis(

            recon,

            findings,

            skill_context

        )

        return {

            "overview": self.overview(

                recon,

                findings

            ),

            "findings": findings,

            "summary": summary

        }
    
    def markdown_report(self, recon, analysis):

        reports = Path("reports")

        reports.mkdir(exist_ok=True)

        report = reports / f"{recon['target'].replace('.','_')}.md"

        with open(report, "w", encoding="utf-8") as f:

            f.write(f"# Sentinel Report\n\n")

            f.write(f"Target: **{recon['target']}**\n\n")

            f.write(f"Generated: {recon['timestamp']}\n\n")

            f.write("---\n\n")

            f.write("## Statistics\n\n")

            for k, v in analysis["overview"].items():

                f.write(f"- **{k}** : {v}\n")

            f.write("\n---\n\n")

            f.write("# AI Analysis\n\n")

            f.write(analysis["summary"])

        return report


    def scan(self, target):

        target = self.normalize(target)

        print()

        print("=" * 60)

        print("Running Recon Pipeline")

        print("=" * 60)

        print()

        recon = self.run_pipeline(target)

        analysis = self.analyze(

            recon,

            ""
        )

        self.save(

            recon,

            analysis["summary"]

        )

        report = self.markdown_report(

            recon,

            analysis

        )

        return {

            "target": target,

            "report": str(report),

            "analysis": analysis,

            "recon": recon

        }


if __name__ == "__main__":

    engine = ReconEngine()

    result = engine.scan("meta.com")

    print()

    print("=" * 60)

    print("SCAN COMPLETE")

    print("=" * 60)

    print()

    print("Target")

    print(result["target"])

    print()

    print("Report")

    print(result["report"])

    print()

    print(result["analysis"]["overview"])

    print()

    print(result["analysis"]["summary"])

