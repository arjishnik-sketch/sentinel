"""Offline tests for the real tool-execution layer (no network, no real tools).

The runner exposes `_resolve` / `_runner` seams so we can drive every branch
without touching the filesystem or spawning processes.
"""
import subprocess
import types

import pytest

from app.tools.resolver import plan_install, InstallRecipe
from app.tools import runner as R
from app.tools import parsers as P


def _proc(returncode=0, stdout="", stderr=""):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


# ---- resolver recipes -------------------------------------------------------

def test_plan_install_known_and_unknown():
    r = plan_install("subfinder")
    assert isinstance(r, InstallRecipe) and r.command[0] == "go"
    assert plan_install("totally-unknown-tool-xyz") is None


# ---- ensure_available: never installs without approval ----------------------

def test_present_tool_is_not_installed():
    calls = []
    path, installed = R.ensure_available(
        "httpx",
        _resolve=lambda t: "/usr/bin/httpx",
        _runner=lambda *a, **k: calls.append(a) or _proc(),
    )
    assert path == "/usr/bin/httpx" and installed is False
    assert calls == []  # nothing was run


def test_missing_tool_default_deny_raises():
    def missing(_):
        raise FileNotFoundError()

    with pytest.raises(R.ApprovalDenied):
        R.ensure_available(  # approve omitted -> default deny
            "subfinder", _resolve=missing, _runner=lambda *a, **k: _proc()
        )


def test_missing_tool_unknown_recipe_raises():
    def missing(_):
        raise FileNotFoundError()

    with pytest.raises(R.ToolUnavailable):
        R.ensure_available(
            "no-such-tool", approve=lambda t, r: True, _resolve=missing
        )


def test_missing_tool_approved_installs_then_resolves():
    state = {"installed": False}
    ran = []

    def resolve(_):
        if state["installed"]:
            return "/root/go/bin/subfinder"
        raise FileNotFoundError()

    def run(argv, **kw):
        ran.append(tuple(argv))
        state["installed"] = True
        return _proc(returncode=0)

    seen = {}
    path, installed = R.ensure_available(
        "subfinder",
        approve=lambda t, r: seen.setdefault("recipe", r) or True,
        _resolve=resolve,
        _runner=run,
    )
    assert installed is True and path.endswith("subfinder")
    assert ran and ran[0] == plan_install("subfinder").command
    assert seen["recipe"].tool == "subfinder"  # recipe surfaced to approver


def test_failed_install_raises():
    def missing(_):
        raise FileNotFoundError()

    with pytest.raises(R.ToolUnavailable):
        R.ensure_available(
            "ffuf",
            approve=lambda t, r: True,
            _resolve=missing,
            _runner=lambda *a, **k: _proc(returncode=1, stderr="boom"),
        )


# ---- run_tool ---------------------------------------------------------------

def test_run_tool_captures_output():
    res = R.run_tool(
        "katana",
        ["-u", "http://x"],
        _resolve=lambda t: "/bin/katana",
        _runner=lambda argv, **k: _proc(stdout="http://x/a\nhttp://x/b\n"),
    )
    assert res.ok and res.returncode == 0
    assert res.lines() == ["http://x/a", "http://x/b"]
    assert res.argv[0] == "/bin/katana" and "-u" in res.argv


def test_run_tool_timeout():
    def boom(argv, **k):
        raise subprocess.TimeoutExpired(cmd=argv, timeout=1)

    res = R.run_tool("nuclei", _resolve=lambda t: "/bin/nuclei", _runner=boom)
    assert res.timed_out is True and res.returncode is None and res.ok is False


# ---- parsers ----------------------------------------------------------------

def test_parse_url_lines_dedup():
    assert P.parse_url_lines("http://a/1\nhttp://a/1\nhttp://a/2\ngarbage\n") == [
        "http://a/1",
        "http://a/2",
    ]


def test_parse_subfinder_lines():
    assert P.parse_subfinder_lines("api.x.com\nx.com\nnot a host\n") == [
        "api.x.com",
        "x.com",
    ]


def test_parse_httpx_jsonl():
    rows = P.parse_httpx_jsonl(
        '{"url":"http://x","status_code":200,"tech":["nginx"]}\nbad\n'
    )
    assert rows == [
        {
            "url": "http://x",
            "status_code": 200,
            "title": None,
            "webserver": None,
            "tech": ("nginx",),
            "content_type": None,
        }
    ]


def test_parse_nuclei_jsonl_and_hosts():
    hits = P.parse_nuclei_jsonl(
        '{"template-id":"cve","info":{"severity":"HIGH","name":"n"},"matched-at":"http://x:8080/a"}'
    )
    assert hits[0]["severity"] == "high" and hits[0]["template_id"] == "cve"
    assert P.hosts_from_urls(["http://x:8080/a", "https://y/b"]) == ["x:8080", "y"]
