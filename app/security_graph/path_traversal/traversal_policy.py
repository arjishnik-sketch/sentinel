"""
Operator-supplied path-traversal / LFI oracle (the file-surface declaration).

Pure DATA, exactly like :mod:`app.security_graph.xss.xss_policy`. It is
deliberately **target-agnostic**: the engine holds no knowledge of any
particular site, route, or parameter. Everything specific to a target — which
endpoint reads which file parameter — arrives here as declared ground truth
(typed by an operator, or synthesized from live recon). Point Sentinel at a
different stack and only this data changes; not a line of engine.

An operator declares a set of *checks*, each naming one request parameter that
flows into a filesystem path:

    GET  /download   ?file=…    (query)
    GET  /view       ?path=…    (query)
    POST /render     {"tpl": …} (JSON body)

The declared parameter makes no security claim on its own. It only poses a
question the deterministic judge answers with an **OS-canary differential** on
the live target: a *control* probe carries a benign, traversal-free, non-OS
filename (which cannot leak a system file), and a *ladder* of payload probes
carry directory-escape shapes aimed at cross-OS canary files
(``../../../../etc/passwd``, ``..\\..\\..\\windows\\win.ini``, absolute paths,
null-byte truncation). Path traversal is CONFIRMED only when a payload response
contains an **OS-file invariant** — ``root:x:0:0:`` for ``/etc/passwd``, a
``[fonts]``/``[extensions]`` section for ``win.ini`` — that is ABSENT from the
control response. A single status code is never itself the verdict; the leaked
system-file signature is, and the control anchors it (an app whose every
response already carries the invariant is INCONCLUSIVE, never a false positive).
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any


# Where a declared parameter lives in the request. Each maps to one unambiguous
# way of injecting the payload — no target-specific body semantics are assumed.
_LOCATIONS = frozenset({"query", "body_form", "body_json"})

_ALLOWED_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})

# The benign, traversal-free, non-OS filename the CONTROL probe sends. It carries
# no directory-escape and names no OS file, so a well-behaved endpoint answers it
# with a legitimate (or not-found) response that CANNOT contain an OS-file
# invariant — exactly the attribution anchor the judge needs: an invariant that
# appears ONLY under a traversal payload, never in this baseline, is attributable
# to directory escape and not to a page that merely mentions "root". It is
# deliberately fixed (not random): the payloads and invariants are fixed OS
# canaries too, so the remediation verifier reconstructs the identical
# differential without any per-hypothesis state.
CONTROL_VALUE = "sentinel-baseline.txt"


# OS-file invariants: signatures a leaked system file uniquely contains and that
# a normal application response could never produce by coincidence. Each is
# (os_label, compiled_regex):
#   /etc/passwd -> "root:<pw>:0:0:" — the root account line (name, password
#                  field, uid 0, gid 0), the canonical POSIX passwd invariant.
#   win.ini     -> a "[fonts]" / "[extensions]" / "[mci extensions]" section
#                  header — the canonical Windows win.ini invariant.
_CANARY_INVARIANTS: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("etc_passwd", re.compile(r"root:[^:\r\n]*:0:0:")),
    (
        "win_ini",
        re.compile(r"\[(?:fonts|extensions|mci extensions)\]", re.IGNORECASE),
    ),
)


# The traversal payload ladder: (label, value). Each value is a genuine
# directory-escape / absolute-path shape aimed at a cross-OS canary file and —
# critically — each also matches the enforcer's ``traversal`` request-guard
# signature family (a ``../`` or ``..\`` escape, and/or the literal ``etc/passwd``
# / ``win.ini`` filename), so the exact shapes the judge keys on are the ones the
# virtual patch blocks — which is what lets the fix be PROVEN. The judge is
# shape-agnostic — it only asks whether SOME payload leaked an OS invariant absent
# from the control — so this ladder can grow freely (more encodings, more canary
# files) without touching the judge.
_TRAVERSAL_PAYLOADS: tuple[tuple[str, str], ...] = (
    ("posix_dotdot", "../../../../../../etc/passwd"),
    ("posix_nested", "....//....//....//....//....//....//etc/passwd"),
    ("posix_abs", "/etc/passwd"),
    ("posix_nullbyte", "../../../../../../etc/passwd\x00.png"),
    ("win_dotdot", "..\\..\\..\\..\\..\\..\\windows\\win.ini"),
    ("win_abs", "C:\\windows\\win.ini"),
)


def traversal_payloads() -> tuple[tuple[str, str], ...]:
    """The (label, value) traversal payload ladder (the fixed table)."""
    return tuple(_TRAVERSAL_PAYLOADS)


def canary_invariants() -> tuple[tuple[str, "re.Pattern[str]"], ...]:
    """The (os_label, compiled invariant regex) OS-file canaries (fixed table)."""
    return tuple(_CANARY_INVARIANTS)


def leaked_canary(body: str) -> str | None:
    """The os_label of the FIRST OS-file invariant present in `body`, else None.

    Pure. This is the load-bearing signal: a match means a system file's
    invariant content appeared in the response — something no normal application
    body contains.
    """
    if not isinstance(body, str) or not body:
        return None
    for label, pattern in _CANARY_INVARIANTS:
        if pattern.search(body):
            return label
    return None

@dataclass(frozen=True)
class TraversalCheck:
    """One declared path-traversal-surface probe.

    `param` in `location` is filled with the benign control filename for the
    control probe, and with each directory-escape payload for the payload probes.
    `method`/`path` name the endpoint. No benign value is needed — the control
    filename and the payload/invariant tables are fixed module data the pure judge
    reads back.
    """

    method: str
    path: str
    param: str
    location: str = "query"
    severity: str = "HIGH"
    rationale: str = ""


@dataclass(frozen=True)
class TraversalPolicy:
    checks: tuple[TraversalCheck, ...] = ()


def _as_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"path-traversal matrix: '{field_name}' must be a non-empty string."
        )
    return value.strip()


def _parse_check(payload: Any) -> TraversalCheck:
    if not isinstance(payload, dict):
        raise ValueError("path-traversal matrix: each check must be an object.")

    method = _as_str(payload.get("method", "GET"), "checks[].method").upper()
    path = _as_str(payload.get("path"), "checks[].path")
    param = _as_str(payload.get("param"), "checks[].param")

    location = payload.get("location", "query")
    location = _as_str(location, "checks[].location").lower()
    if location not in _LOCATIONS:
        raise ValueError(
            "path-traversal matrix: 'location' must be one of "
            f"{sorted(_LOCATIONS)}, got {location!r}."
        )

    severity = payload.get("severity", "HIGH")
    severity = _as_str(severity, "checks[].severity").upper()
    if severity not in _ALLOWED_SEVERITIES:
        raise ValueError(
            "path-traversal matrix: 'severity' must be one of "
            f"{sorted(_ALLOWED_SEVERITIES)}, got {severity!r}."
        )

    rationale = payload.get("rationale", "")
    if rationale and not isinstance(rationale, str):
        raise ValueError("path-traversal matrix: 'rationale' must be a string.")

    return TraversalCheck(
        method=method,
        path=path,
        param=param,
        location=location,
        severity=severity,
        rationale=rationale.strip() if isinstance(rationale, str) else "",
    )

def parse_traversal_policy(payload: Any) -> TraversalPolicy:
    """Validate and normalise a decoded path-traversal matrix.

    Accepts a dedicated document ``{"path_traversal_matrix": {...}}`` (or the
    shorter ``{"traversal_matrix": {...}}``) or a combined access-policy document
    that also carries one of those sections — so a single operator file drives
    every vulnerability class. Returns an empty policy (no checks) when none is
    declared, which the caller treats as "path-traversal pass not requested".
    """
    if not isinstance(payload, dict):
        raise ValueError(
            "path-traversal matrix: top level must be a JSON object."
        )

    matrix = payload.get("path_traversal_matrix")
    if matrix is None:
        matrix = payload.get("traversal_matrix", payload)
    if not isinstance(matrix, dict):
        raise ValueError(
            "path-traversal matrix: 'path_traversal_matrix' must be an object."
        )

    checks_raw = matrix.get("checks", [])
    if not isinstance(checks_raw, (list, tuple)):
        raise ValueError("path-traversal matrix: 'checks' must be a list.")
    checks = tuple(_parse_check(item) for item in checks_raw)

    return TraversalPolicy(checks=checks)


def load_traversal_policy(path: str | Path) -> TraversalPolicy:
    """Load and validate a path-traversal matrix JSON file from disk."""
    text = Path(path).read_text(encoding="utf-8")
    return parse_traversal_policy(json.loads(text))
