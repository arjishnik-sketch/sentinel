"""
Source-code remediation (auto-detect) — the optional root-cause half.

Activates only when the operator also provides the target's source
repository. It detects the web framework, locates the route handler that
serves the violated method+path, and emits a minimal, clearly-marked
authorization-guard patch as a clean unified diff. When the handler cannot
be pinpointed, or the stack has no known guard idiom, it degrades to an
ADVISORY guard + guidance rather than guessing.

This half is never *proven live* here — applying it requires the operator's
own rebuild. The enforcement shield carries the live PROVE. Everything in
this module is read-only against the repo, deterministic, and framework-
general (no target-specific strings).
"""

from __future__ import annotations

import difflib
import os
from pathlib import Path

from .model import AccessControlRule, SourcePatch


__all__ = ["detect_framework", "generate_source_patch"]


_SKIP_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        "dist",
        "build",
        "out",
        "vendor",
        ".venv",
        "venv",
        "__pycache__",
        "target",
        ".next",
        "coverage",
    }
)

_SOURCE_EXTENSIONS = frozenset(
    {".js", ".ts", ".jsx", ".tsx", ".py", ".go", ".java", ".rb"}
)

_MAX_FILES = 2000
_MAX_FILE_BYTES = 512 * 1024

_GENERATED_FRAMEWORKS = frozenset(
    {"express", "koa", "fastify", "flask", "django", "fastapi", "spring", "rails"}
)

def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def detect_framework(source_root: str | Path) -> str:
    """Classify the repo's web framework from its root manifests."""
    root = Path(source_root)

    def manifest(name: str) -> str:
        text = _read_text(root / name)
        return text.lower() if text else ""

    package_json = manifest("package.json")
    if package_json:
        for name in ("express", "koa", "fastify"):
            if f'"{name}"' in package_json or name in package_json:
                return name

    python_manifests = (
        manifest("requirements.txt")
        + manifest("pyproject.toml")
        + manifest("Pipfile")
    )
    if python_manifests:
        for name in ("django", "fastapi", "flask"):
            if name in python_manifests:
                return name

    if "spring" in (manifest("pom.xml") + manifest("build.gradle")):
        return "spring"

    if "rails" in manifest("Gemfile"):
        return "rails"

    return "generic"

def _line_references_method(line: str, method: str) -> bool:
    lowered = line.lower()
    method_lower = method.lower()
    # JS/route-builder idioms: app.get( / router.post( ...
    if f".{method_lower}(" in lowered:
        return True
    # Explicit method mentions in decorators / config.
    if f"methods=" in lowered and method_lower in lowered:
        return True
    if f'"{method}"' in line or f"'{method}'" in line:
        return True
    if f"@{method_lower}" in lowered:  # e.g. @app.get / @GetMapping-ish
        return True
    return False


def _locate_handler(root: Path, rule: AccessControlRule):
    """
    Find the source line serving this route.

    Returns ``(relative_path, line_index)`` for the best candidate, or
    None. A line that also references the HTTP method outranks a
    path-only line; ties resolve by deterministic path ordering.
    """
    best_path_only = None
    files_scanned = 0

    for current, dirnames, filenames in os.walk(root):
        # Prune skip dirs in place (any depth).
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for filename in sorted(filenames):
            if Path(filename).suffix not in _SOURCE_EXTENSIONS:
                continue
            if files_scanned >= _MAX_FILES:
                break
            files_scanned += 1

            file_path = Path(current) / filename
            text = _read_text(file_path)
            if not text or rule.path not in text:
                continue

            rel = os.path.relpath(file_path, root).replace(os.sep, "/")
            for index, line in enumerate(text.splitlines()):
                if rule.path not in line:
                    continue
                if _line_references_method(line, rule.method):
                    return rel, index
                if best_path_only is None:
                    best_path_only = (rel, index)

    return best_path_only

def _guard_lines(framework: str, rule: AccessControlRule) -> list[str] | None:
    """
    Minimal, framework-appropriate authorization guard as source lines.

    Lines carry their own *relative* indentation; the caller prefixes the
    handler's base indent. Returns None for stacks with no known idiom.
    """
    principal = rule.principal_name
    tag = f"enforce authorization for {rule.action} {rule.path} (deny {principal})"

    if framework in ("express", "koa", "fastify"):
        return [
            f"// Sentinel remediation: {tag}",
            "if (!req.isAuthenticated || !req.isAuthenticated()) "
            "{ return res.status(403).json({ error: 'Forbidden' }); }",
        ]
    if framework == "flask":
        return [
            f"# Sentinel remediation: {tag}",
            'if not getattr(g, "user", None):',
            "    abort(403)",
        ]
    if framework == "django":
        return [
            f"# Sentinel remediation: {tag}",
            "if not request.user.is_authenticated:",
            "    return HttpResponseForbidden()",
        ]
    if framework == "fastapi":
        return [
            f"# Sentinel remediation: {tag}",
            "# wire a dependency: user = Depends(require_authenticated)",
            "if user is None:",
            "    raise HTTPException(status_code=403)",
        ]
    if framework == "spring":
        return [
            f"// Sentinel remediation: {tag}",
            '@PreAuthorize("isAuthenticated()")',
        ]
    if framework == "rails":
        return [
            f"# Sentinel remediation: {tag}",
            "before_action :require_authenticated!",
        ]
    return None


def _leading_indent(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]

def generate_source_patch(
    rule: AccessControlRule,
    *,
    source_root: str | None,
) -> SourcePatch:
    """Generate a source-code guard patch for the confirmed route, or advise."""

    if not source_root:
        return SourcePatch(
            status="NOT_PROVIDED",
            guidance=(
                "No target source repository was provided; the enforcement "
                "shield is the deployable fix."
            ),
        )

    root = Path(source_root)
    if not root.is_dir():
        return SourcePatch(
            status="ADVISORY",
            guidance=(
                f"Source path '{source_root}' is not a readable directory; "
                "apply the enforcement shield and add an authorization guard "
                f"on the handler for {rule.method} {rule.path}."
            ),
        )

    framework = detect_framework(root)
    located = _locate_handler(root, rule)

    if located is None:
        return SourcePatch(
            status="ADVISORY",
            framework=framework,
            guidance=(
                f"Route literal '{rule.path}' was not found in source. "
                f"Add an authorization guard denying {rule.principal_name} on "
                f"the {rule.method} {rule.path} handler; deploy the "
                "enforcement shield meanwhile."
            ),
        )

    rel, line_index = located
    guard = _guard_lines(framework, rule)

    if guard is None:
        return SourcePatch(
            status="ADVISORY",
            framework=framework,
            file_path=rel,
            guidance=(
                f"Handler located at {rel}:{line_index + 1}. Framework has no "
                f"built-in guard idiom; add an authorization check denying "
                f"{rule.principal_name} before this {rule.method} handler."
            ),
        )

    original = _read_text(root / rel)
    if original is None:
        return SourcePatch(
            status="ADVISORY",
            framework=framework,
            file_path=rel,
            guidance=f"Handler file {rel} became unreadable while patching.",
        )

    original_lines = original.splitlines(keepends=True)
    if line_index >= len(original_lines):
        line_index = max(0, len(original_lines) - 1)

    base_indent = _leading_indent(original_lines[line_index])
    guard_lines = [f"{base_indent}{line}\n" for line in guard]
    patched_lines = (
        original_lines[:line_index]
        + guard_lines
        + original_lines[line_index:]
    )

    diff = "".join(
        difflib.unified_diff(
            original_lines,
            patched_lines,
            fromfile=f"a/{rel}",
            tofile=f"b/{rel}",
            lineterm="\n",
        )
    )

    return SourcePatch(
        status="GENERATED",
        framework=framework,
        file_path=rel,
        unified_diff=diff,
        guidance=(
            f"Inserted a minimal {framework} authorization guard before "
            f"{rel}:{line_index + 1}. Review, then rebuild to enforce at the "
            "source; the shield already enforces it live."
        ),
    )
