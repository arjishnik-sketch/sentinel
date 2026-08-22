"""
Dependency-free reconnaissance crawler.

This module is a fallback surface-discovery source for environments
where external recon binaries (subfinder / httpx / katana) are not
installed. It uses only the Python standard library.

Discovery is bounded, same-origin, and non-destructive:

  - it confirms the target origin is reachable (alive);
  - it crawls same-origin HTML up to a bounded page count and depth;
  - it records linked assets (scripts, stylesheets, form actions);
  - it mines first-party JavaScript for same-origin API route
    references and surfaces them as discovered URLs.

Discovering a URL is NOT a security claim. It records only that the
application itself references the URL, which is a justified reason to
investigate authorization behaviour later in the research pipeline.
The crawler never asserts a vulnerability, an authorization outcome,
or a policy. It only reports observed surface.
"""

from __future__ import annotations

import re
from collections import deque
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import urldefrag, urljoin, urlparse
from urllib.request import Request, urlopen


# Static assets are recorded as surface but never enqueued for HTML
# link expansion.
_ASSET_SUFFIXES = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".webm",
    ".mp3",
    ".pdf",
    ".zip",
    ".map",
)


# Same-origin API route references embedded in first-party JavaScript.
# Only conventional API path prefixes are promoted; arbitrary strings
# in a bundle are ignored. Matches both root-relative ("/rest/...")
# and absolute ("https://host/api/...") references.
_API_ROUTE_PATTERN = re.compile(
    r"""['"`]"""
    r"""("""
    r"""(?:https?://[^'"`\s]+)?"""
    r"""/(?:rest|api|graphql|v\d+|internal|admin|actuator)"""
    r"""(?:/[^'"`\s?#]*)?"""
    r""")"""
    r"""['"`]""",
    re.IGNORECASE,
)


class _LinkExtractor(HTMLParser):
    """Collect hyperlink and script references from an HTML document."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        attributes = dict(attrs)

        if tag == "a" and attributes.get("href"):
            self.links.append(attributes["href"])

        elif tag == "script" and attributes.get("src"):
            self.scripts.append(attributes["src"])

        elif tag == "link" and attributes.get("href"):
            self.links.append(attributes["href"])

        elif tag == "form" and attributes.get("action"):
            self.links.append(attributes["action"])

        elif tag in ("area", "iframe"):
            reference = attributes.get("href") or attributes.get("src")
            if reference:
                self.links.append(reference)


def _normalize_base(target: str) -> str:
    base = target.strip()

    if "://" not in base:
        base = f"http://{base}"

    return base


def crawl_target(
    target: str,
    *,
    max_pages: int = 40,
    max_depth: int = 2,
    max_js: int = 12,
    max_api_routes: int = 80,
    timeout: float = 6.0,
    read_limit: int = 3_000_000,
    user_agent: str = "Sentinel/1.0 (+bounded-recon)",
) -> dict:
    """
    Perform bounded same-origin discovery against ``target``.

    Returns a recon fragment compatible with the ingest pipeline::

        {"alive": [{"url": ..., "status_code": ...}], "crawl": [url, ...]}

    All requests are GET, same-origin, and size/time bounded. Hosts
    other than the target origin are never contacted.
    """

    base = _normalize_base(target)
    parsed = urlparse(base)
    origin_host = parsed.netloc.lower()

    if not origin_host:
        return {"alive": [], "crawl": []}

    def same_origin(url: str) -> bool:
        candidate = urlparse(url)

        if candidate.scheme and candidate.scheme.lower() not in (
            "http",
            "https",
        ):
            return False

        return (
            not candidate.netloc
            or candidate.netloc.lower() == origin_host
        )

    def fetch(url: str):
        request = Request(
            url,
            headers={"User-Agent": user_agent},
            method="GET",
        )

        try:
            with urlopen(request, timeout=timeout) as response:
                content_type = response.headers.get_content_type()
                body = response.read(read_limit)
                return response.status, content_type, body

        except HTTPError as exc:
            # An HTTP error still confirms the URL exists as surface.
            return exc.code, "", b""

        except (URLError, TimeoutError, OSError, ValueError):
            return None, "", b""

        except Exception:
            return None, "", b""

    alive: list[dict] = []
    crawl_urls: set[str] = set()
    js_urls: list[str] = []

    # Confirm the origin is reachable before spending any crawl budget.
    root_status, _root_ctype, _root_body = fetch(base)

    if root_status is None:
        return {"alive": [], "crawl": []}

    alive.append({"url": base, "status_code": root_status})

    seen: set[str] = {urldefrag(base)[0]}
    queue: deque[tuple[str, int]] = deque([(base, 0)])

    while queue and len(seen) <= max_pages:
        url, depth = queue.popleft()

        status, content_type, body = fetch(url)

        if status is None:
            continue

        crawl_urls.add(url)

        if "html" not in content_type:
            continue

        text = body.decode("utf-8", "ignore")

        extractor = _LinkExtractor()

        try:
            extractor.feed(text)
        except Exception:
            pass

        for source in extractor.scripts:
            absolute = urldefrag(urljoin(url, source))[0]

            if not same_origin(absolute):
                continue

            crawl_urls.add(absolute)

            if absolute.lower().endswith(".js") and absolute not in js_urls:
                js_urls.append(absolute)

        if depth >= max_depth:
            continue

        for href in extractor.links:
            if href.startswith(
                ("mailto:", "tel:", "javascript:", "data:", "#")
            ):
                continue

            absolute = urldefrag(urljoin(url, href))[0]

            if not same_origin(absolute):
                continue

            if absolute.lower().endswith(_ASSET_SUFFIXES):
                crawl_urls.add(absolute)
                continue

            if absolute not in seen and len(seen) <= max_pages:
                seen.add(absolute)
                queue.append((absolute, depth + 1))

    # Mine first-party JavaScript for same-origin API route references.
    mined: set[str] = set()

    for js_url in js_urls[:max_js]:
        if len(mined) >= max_api_routes:
            break

        status, _content_type, body = fetch(js_url)

        if status is None or not body:
            continue

        text = body.decode("utf-8", "ignore")

        for match in _API_ROUTE_PATTERN.finditer(text):
            route = match.group(1).strip()

            if not route:
                continue

            # Ignore interpolation/template-only references.
            if "${" in route or "{{" in route or "+" in route:
                continue

            if route.startswith(("http://", "https://")):
                api_url = route
            else:
                api_url = urljoin(base, route)

            if not same_origin(api_url):
                continue

            mined.add(api_url)

            if len(mined) >= max_api_routes:
                break

    crawl_urls.update(mined)

    return {
        "alive": alive,
        "crawl": sorted(crawl_urls),
    }
