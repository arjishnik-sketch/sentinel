"""Pytest configuration + shared fixtures for the live-integration harness.

Registers the ``live`` marker and the reachability-gated target fixtures the
tests under ``tests/live/`` use. The default offline run (plain ``pytest``)
deselects ``live`` via ``addopts = -m 'not live'`` (see pyproject.toml), so this
changes nothing for the offline suite. The live suite runs only under
``pytest -m live`` AND only when its target is actually reachable — a dev box or
CI without the vulnerable apps up SKIPS cleanly rather than erroring.

Targets (override via env, else these defaults):
  SENTINEL_JUICE_URL   OWASP Juice Shop     http://localhost:3000
  SENTINEL_VAMPI_URL   VAmPI (vulnerable)   http://localhost:5001

See docker-compose.yml to stand the targets up locally, and
.github/workflows/live.yml for the CI job.
"""
from __future__ import annotations

import os

import pytest
import requests

JUICE_URL = (os.environ.get("SENTINEL_JUICE_URL") or "http://localhost:3000").rstrip("/")
VAMPI_URL = (os.environ.get("SENTINEL_VAMPI_URL") or "http://localhost:5001").rstrip("/")

# Requesting one of these fixtures marks a test as touching a live vulnerable
# target. Any such test is auto-tagged `live` (see pytest_collection_modifyitems)
# so an author can never forget the marker and leak a network test into the
# offline `-m 'not live'` run.
_LIVE_FIXTURES = {"juice_url", "vampi_url"}


def _reachable(url: str, *, timeout: float = 3.0) -> bool:
    """True if the host answers at all. Any HTTP response (even 4xx/5xx) counts —
    requests only raises on connection/timeout errors, not on status codes.
    Never raises: an unreachable target is a clean False."""
    try:
        requests.get(url, timeout=timeout)
        return True
    except Exception:
        return False


@pytest.fixture(scope="session")
def juice_url() -> str:
    if not _reachable(JUICE_URL):
        pytest.skip(f"OWASP Juice Shop not reachable at {JUICE_URL} "
                    "(start the target or set SENTINEL_JUICE_URL)")
    return JUICE_URL


@pytest.fixture(scope="session")
def vampi_url() -> str:
    if not _reachable(VAMPI_URL):
        pytest.skip(f"VAmPI not reachable at {VAMPI_URL} "
                    "(start the target or set SENTINEL_VAMPI_URL)")
    # VAmPI boots with an empty DB; GET /createdb seeds the default users
    # (name1/name2) the path-segment differential anchors on. Idempotent and
    # best-effort — CI also does this, but self-healing here helps local runs.
    try:
        requests.get(f"{VAMPI_URL}/createdb", timeout=10)
    except Exception:
        pass
    return VAMPI_URL


def pytest_collection_modifyitems(config, items):
    """Auto-apply the `live` marker to any test requesting a live-target fixture,
    so the offline `-m 'not live'` default reliably deselects the whole live tier."""
    for item in items:
        if _LIVE_FIXTURES & set(getattr(item, "fixturenames", ())):
            item.add_marker("live")
