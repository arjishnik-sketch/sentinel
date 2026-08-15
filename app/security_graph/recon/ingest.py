from urllib.parse import urlparse

from ..graph import SecurityGraph
from ..models import (
    Endpoint,
    Observation,
    Relationship,
    Resource,
)


def _host_resource_id(host: str) -> str:
    return f"host:{host}"


def _endpoint_id(url: str) -> str:
    return f"endpoint:{url}"


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
