from urllib.parse import urlparse

from ..graph import SecurityGraph
from ..models import (
    Endpoint,
    Observation,
    Relationship,
    Resource,
)

# B690R21R5_DYNAMIC_API_MATERIALIZER
import re
from urllib.request import urlopen
from urllib.parse import urljoin, urlparse


def _host_resource_id(host: str) -> str:
    return f"host:{host}"


def _endpoint_id(url: str) -> str:
    return f"endpoint:{url}"



def _materialize_javascript_api_observations(
    graph: SecurityGraph,
    target: str,
    javascript_urls: list[str],
) -> None:
    """Materialize bounded same-origin request references from JavaScript."""

    request_call_pattern = re.compile(
        r"""
        (?:
            \b(?:http|this\.http)\s*\.\s*
            (?:get|post|put|patch|delete|request)
            \s*\(
            |
            \bfetch\s*\(
            |
            \b(?:request|ajax|send)\s*\(
        )
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    string_pattern = re.compile(
        r"""['"`]([^'"`]{1,500})['"`]"""
    )

    materialized: set[str] = set()

    for js_url in javascript_urls:
        if not isinstance(js_url, str) or not js_url.strip():
            continue

        js_url = js_url.strip()

        try:
            body = urlopen(
                js_url,
                timeout=5,
            ).read(2_000_000)

            text = body.decode(
                "utf-8",
                "ignore",
            )

        except Exception:
            continue

        for call in request_call_pattern.finditer(text):

            # Only inspect a bounded region immediately following
            # the request call. This prevents arbitrary application
            # strings elsewhere in a large JavaScript bundle from
            # becoming endpoints.
            window = text[
                call.end():
                min(len(text), call.end() + 1200)
            ]

            for string_match in string_pattern.finditer(window):

                route = string_match.group(1).strip()

                if not route:
                    continue

                # Recover the STATIC path skeleton from a template literal.
                # SPA bundles routinely build an API URL by interpolating a host
                # prefix and/or a parameter value into one template literal, e.g.
                # `${this.hostServer}/rest/products/search?q=${term}`. Dropping
                # every interpolated string would blind recon to exactly these
                # real endpoints, so instead collapse the `${...}` / `{{...}}`
                # tokens and keep the surrounding literal segments. The result
                # still passes through every same-origin / leading-slash / asset
                # guard below, and any bogus remainder simply yields no endpoint
                # of consequence downstream (every class judges what it probes).
                if "${" in route or "{{" in route:
                    route = re.sub(r"\$\{[^{}]*\}", "", route)
                    route = re.sub(r"\{\{[^{}]*\}\}", "", route)
                    route = route.strip()
                    # A residual unbalanced interpolation is unusable — skip it.
                    if not route or "${" in route or "{{" in route:
                        continue

                # Ignore protocol-relative external references.
                if route.startswith("//"):
                    continue

                # Absolute URLs are accepted only when same-origin.
                if route.startswith(
                    ("http://", "https://")
                ):
                    api_url = route

                # Root-relative application routes.
                elif route.startswith("/"):
                    api_url = urljoin(
                        js_url,
                        route,
                    )

                else:
                    continue

                js_origin = urlparse(js_url).netloc
                api_origin = urlparse(api_url).netloc

                if not api_origin:
                    continue

                if js_origin and api_origin != js_origin:
                    continue

                parsed = urlparse(api_url)

                if not parsed.hostname:
                    continue

                # Avoid treating static assets as API candidates.
                if parsed.path.lower().endswith(
                    (
                        ".js",
                        ".css",
                        ".ico",
                        ".png",
                        ".jpg",
                        ".jpeg",
                        ".gif",
                        ".svg",
                        ".woff",
                        ".woff2",
                        ".ttf",
                    )
                ):
                    continue

                materialized.add(api_url)

    observation_number = len(graph.observations) + 1

    for api_url in sorted(materialized):

        endpoint_id = _endpoint_id(api_url)

        graph.add_endpoint(
            Endpoint(
                id=endpoint_id,
                method="GET",
                url=api_url,
            )
        )

        observation_id = f"recon:api:{observation_number}"

        if observation_id in graph.observations:
            continue

        graph.add_observation(
            Observation(
                id=observation_id,
                kind="recon_api",
                subject=endpoint_id,
                data={
                    "url": api_url,
                    "target": target,
                    "source": "javascript_request_reference",
                },
                evidence_ids=(),
            )
        )

        observation_number += 1
def ingest_recon(
    graph: SecurityGraph,
    recon: dict,
    findings: dict,
) -> None:
    target = recon["target"]

    target_id = f"target:{target}"

    graph.add_resource(
        Resource(
            id=target_id,
            type="target",
            name=target,
        )
    )

    # Hosts discovered by recon.
    hosts = set()

    for item in recon.get("alive", []):
        value = item.get("url") if isinstance(item, dict) else item

        if not value:
            continue

        parsed = urlparse(value)

        if parsed.hostname:
            hosts.add(parsed.hostname.lower())

    for host in sorted(hosts):
        host_id = _host_resource_id(host)

        graph.add_resource(
            Resource(
                id=host_id,
                type="host",
                name=host,
            )
        )

        graph.add_relationship(
            Relationship(
                source=target_id,
                relation="contains",
                target=host_id,
            )
        )

    # Crawled URLs become endpoints.
    for url in recon.get("crawl", []):
        if not isinstance(url, str):
            continue

        parsed = urlparse(url)

        if not parsed.hostname:
            continue

        endpoint_id = _endpoint_id(url)
        host_id = _host_resource_id(parsed.hostname.lower())

        graph.add_endpoint(
            Endpoint(
                id=endpoint_id,
                method="GET",
                url=url,
            )
        )

        # Ensure the host exists even if httpx did not provide it.
        if host_id not in graph.resources:
            graph.add_resource(
                Resource(
                    id=host_id,
                    type="host",
                    name=parsed.hostname.lower(),
                )
            )

        graph.add_relationship(
            Relationship(
                source=host_id,
                relation="exposes",
                target=endpoint_id,
            )
        )

    # Record extracted attack-surface observations.
    observation_groups = (
        ("login", findings.get("logins", [])),
        ("admin", findings.get("admins", [])),
        ("api", findings.get("apis", [])),
        ("graphql", findings.get("graphql", [])),
        ("swagger", findings.get("swagger", [])),
        ("upload", findings.get("uploads", [])),
        ("javascript", findings.get("javascript", [])),
    )

    observation_number = 0

    for kind, urls in observation_groups:
        for url in urls:
            observation_number += 1

            graph.add_observation(
                Observation(
                    id=f"recon:{kind}:{observation_number}",
                    kind=f"recon_{kind}",
                    subject=_endpoint_id(url),
                    data={
                        "url": url,
                        "target": target,
                    },
                )
            )

    # Parameters are attached to the endpoint where they were observed.
    for url in recon.get("crawl", []):
        if not isinstance(url, str) or "?" not in url:
            continue

        endpoint_id = _endpoint_id(url)

        query = url.split("?", 1)[1]

        for pair in query.split("&"):
            if "=" not in pair:
                continue

            parameter = pair.split("=", 1)[0].strip()

            if not parameter:
                continue

            observation_number += 1

            graph.add_observation(
                Observation(
                    id=f"recon:parameter:{observation_number}",
                    kind="recon_parameter",
                    subject=endpoint_id,
                    data={
                        "parameter": parameter,
                        "url": url,
                        "target": target,
                    },
                )
            )
    # B690R21R5_DYNAMIC_API_MATERIALIZER
    _materialize_javascript_api_observations(
        graph,
        target,
        findings.get("javascript", []),
    )
