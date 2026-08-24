"""Forgiving parsers that turn recon-tool stdout into structured data.

Tools differ and change; we extract only what the engine consumes (URLs, hosts,
prober rows, template hits) and silently ignore anything malformed.
"""
from __future__ import annotations

import json
from urllib.parse import urlparse


def _json_lines(text):
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line[0] not in "{[":
            continue
        try:
            yield json.loads(line)
        except ValueError:
            continue


def parse_url_lines(text):
    """katana / gau / waybackurls: one URL per line."""
    out, seen = [], set()
    for line in (text or "").splitlines():
        u = line.strip()
        if u and "://" in u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def parse_subfinder_lines(text):
    """subfinder: one hostname per line."""
    out, seen = [], set()
    for line in (text or "").splitlines():
        h = line.strip().lower()
        if h and "." in h and " " not in h and h not in seen:
            seen.add(h)
            out.append(h)
    return out


def parse_httpx_jsonl(text):
    """httpx -json: rows with url/status_code/tech/title/webserver."""
    rows = []
    for obj in _json_lines(text):
        if not isinstance(obj, dict):
            continue
        url = obj.get("url") or obj.get("input")
        if not url:
            continue
        rows.append(
            {
                "url": url,
                "status_code": obj.get("status_code") or obj.get("status-code"),
                "title": obj.get("title"),
                "webserver": obj.get("webserver"),
                "tech": tuple(obj.get("tech") or obj.get("technologies") or ()),
                "content_type": obj.get("content_type") or obj.get("content-type"),
            }
        )
    return rows


def parse_nuclei_jsonl(text):
    """nuclei -jsonl: template-id / severity / matched-at."""
    hits = []
    for obj in _json_lines(text):
        if not isinstance(obj, dict):
            continue
        info = obj.get("info") or {}
        hits.append(
            {
                "template_id": obj.get("template-id") or obj.get("templateID"),
                "name": info.get("name"),
                "severity": (info.get("severity") or "").lower(),
                "matched_at": obj.get("matched-at") or obj.get("host"),
                "type": obj.get("type"),
            }
        )
    return hits


def hosts_from_urls(urls):
    """Distinct netlocs from an iterable of URLs, sorted."""
    hosts = set()
    for u in urls or ():
        netloc = urlparse(u).netloc
        if netloc:
            hosts.add(netloc.lower())
    return sorted(hosts)
