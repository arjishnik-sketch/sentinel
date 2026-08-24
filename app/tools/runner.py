"""Real tool execution with approval-gated auto-install.

This replaces the old preview-only Executor: it actually runs external recon /
exploitation tools and captures their output as structured evidence. When a tool
is missing, Sentinel IDENTIFIES it and the install command itself, then asks the
caller's `approve` callback before running anything — it never installs silently.
"""
from __future__ import annotations

from dataclasses import dataclass
import subprocess
import time

from .resolver import resolve, plan_install, InstallRecipe

DEFAULT_INSTALL_TIMEOUT = 600
DEFAULT_RUN_TIMEOUT = 300


class ApprovalDenied(RuntimeError):
    """Raised when the user declined an auto-install."""


class ToolUnavailable(RuntimeError):
    """Raised when a tool cannot be resolved and cannot be installed."""


@dataclass
class ToolResult:
    tool: str
    argv: tuple
    returncode: "int | None"
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False
    installed: bool = False   # True if we installed the tool during this call

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def lines(self):
        return [ln for ln in self.stdout.splitlines() if ln.strip()]


def _deny(tool, recipe):
    """Default approval callback: never install without an explicit yes."""
    return False


def ensure_available(
    tool,
    *,
    approve=None,
    install_timeout=DEFAULT_INSTALL_TIMEOUT,
    _resolve=resolve,
    _runner=subprocess.run,
):
    """Return (path, installed) for `tool`.

    If the tool is missing, look up an install recipe and ask
    `approve(tool, recipe) -> bool`. Only on an explicit True do we run the
    install and re-resolve. Missing recipe or a False from `approve` raises.
    """

    try:
        return _resolve(tool), False
    except FileNotFoundError:
        pass

    recipe = plan_install(tool)
    if recipe is None:
        raise ToolUnavailable(
            f"{tool} is not installed and no install recipe is known."
        )

    approve = approve or _deny
    if not approve(tool, recipe):
        raise ApprovalDenied(f"install of {tool} declined ({recipe.display})")

    proc = _runner(
        list(recipe.command), capture_output=True, text=True, timeout=install_timeout
    )
    if getattr(proc, "returncode", 1) != 0:
        raise ToolUnavailable(
            f"install of {tool} failed ({recipe.display}): "
            f"{(getattr(proc, 'stderr', '') or '')[:400]}"
        )

    try:
        return _resolve(tool), True
    except FileNotFoundError as exc:
        raise ToolUnavailable(
            f"{tool} still not found after install ({recipe.display})"
        ) from exc


def run_tool(
    tool,
    args=(),
    *,
    approve=None,
    input_text=None,
    timeout=DEFAULT_RUN_TIMEOUT,
    env=None,
    _resolve=resolve,
    _runner=subprocess.run,
) -> ToolResult:
    """Resolve (installing on approval), run `tool args`, capture stdout/stderr."""

    path, installed = ensure_available(
        tool, approve=approve, _resolve=_resolve, _runner=_runner
    )
    argv = [path, *[str(a) for a in args]]

    start = time.monotonic()
    timed_out = False
    try:
        proc = _runner(
            argv,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        returncode, out, err = proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = None
        out = exc.stdout if isinstance(exc.stdout, str) else ""
        err = exc.stderr if isinstance(exc.stderr, str) else ""

    return ToolResult(
        tool=tool,
        argv=tuple(argv),
        returncode=returncode,
        stdout=out,
        stderr=err,
        duration_s=time.monotonic() - start,
        timed_out=timed_out,
        installed=installed,
    )
