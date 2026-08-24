"""Session-aware probing: cookie bisection + session-locked parameter mutation.

Directly implements the two behaviours asked for:
  * "eliminate parts of the cookies to see which are real vs placeholders" ->
    bisect_cookies drops each cookie in turn and re-probes; a cookie is
    LOAD-BEARING iff removing it breaks the authenticated signal (a per-cookie
    differential anchored on the full jar being alive).
  * "while testing login, if it finds a param, mutate it keeping cookies same" ->
    mutate_param holds the captured Cookie header constant and varies one param.

This module PRODUCES evidence and a deterministic session map. It does not
declare vulnerabilities — the technique judges dispose downstream.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

_AUTHED_STATUSES = frozenset({200, 201, 204})


def parse_cookie_header(header):
    pairs = []
    for chunk in (header or "").split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        name, _, value = chunk.partition("=")
        pairs.append((name.strip(), value.strip()))
    return pairs


def render_cookie_header(pairs):
    return "; ".join(f"{n}={v}" for n, v in pairs)


def default_authed(probe):
    """Conservative default anchor: a 2xx success. Redirects/401/403/errors read
    as not-authenticated. Callers with a body marker can pass a stricter fn."""
    return probe.status in _AUTHED_STATUSES


@dataclass
class CookieClass:
    name: str
    load_bearing: bool
    baseline_status: "int | None"
    dropped_status: "int | None"


@dataclass
class CookieReport:
    alive: bool
    baseline_status: "int | None"
    classes: tuple = ()
    note: str = ""

    @property
    def load_bearing(self):
        return tuple(c.name for c in self.classes if c.load_bearing)

    @property
    def placeholders(self):
        return tuple(c.name for c in self.classes if not c.load_bearing)


def bisect_cookies(prober, url, cookie_header, *, authed=default_authed, method="GET", extra_headers=None):
    """Classify each cookie as load-bearing vs placeholder via single-drop diff."""
    pairs = parse_cookie_header(cookie_header)
    extra = dict(extra_headers or {})

    def probe(jar_pairs):
        headers = dict(extra)
        if jar_pairs:
            headers["Cookie"] = render_cookie_header(jar_pairs)
        return prober.request(method, url, headers=headers)

    baseline = probe(pairs)
    if not authed(baseline):
        return CookieReport(
            alive=False,
            baseline_status=baseline.status,
            note="session not alive on full jar; cannot bisect",
        )

    classes = []
    for i, (name, _v) in enumerate(pairs):
        reduced = pairs[:i] + pairs[i + 1 :]
        r = probe(reduced)
        classes.append(
            CookieClass(
                name=name,
                load_bearing=not authed(r),   # dropping it broke auth
                baseline_status=baseline.status,
                dropped_status=r.status,
            )
        )
    return CookieReport(alive=True, baseline_status=baseline.status, classes=tuple(classes))


def _replace_query_param(url, param, value):
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[param] = value
    return urlunparse(p._replace(query=urlencode(q)))


@dataclass
class MutationResult:
    param: str
    baseline: object          # Probe
    mutations: tuple = ()     # tuple[(value, Probe)]


def mutate_param(prober, url, param, values, *, cookie_header=None, method="GET",
                 extra_headers=None, baseline_value=None):
    """Hold the captured session constant, vary one parameter, capture each probe."""
    headers = dict(extra_headers or {})
    if cookie_header:
        headers["Cookie"] = cookie_header

    base_url = url if baseline_value is None else _replace_query_param(url, param, baseline_value)
    baseline = prober.request(method, base_url, headers=headers)

    mutations = []
    for value in values:
        mutated_url = _replace_query_param(url, param, value)
        mutations.append((value, prober.request(method, mutated_url, headers=headers)))

    return MutationResult(param=param, baseline=baseline, mutations=tuple(mutations))
