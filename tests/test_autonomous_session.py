"""Offline tests for the scope-guarded prober + session-aware engine."""
import io
from urllib.error import HTTPError, URLError

import pytest

from app.autonomous.probe import HttpProber, Probe, ScopeError, enforce_scope
from app.autonomous import session as S


class FakeHeaders:
    def __init__(self, items):
        self._items = list(items)

    def items(self):
        return list(self._items)

    def get_all(self, key):
        return [v for k, v in self._items if k.lower() == key.lower()]


class FakeResp:
    def __init__(self, status, headers, body=b""):
        self.status = status
        self.headers = FakeHeaders(headers)
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


# ---- prober scope guard -----------------------------------------------------

def test_scope_refuses_bad_scheme():
    with pytest.raises(ScopeError):
        enforce_scope("file:///etc/passwd", None)


def test_scope_refuses_offhost():
    with pytest.raises(ScopeError):
        enforce_scope("http://evil.com/x", {"shop.test"})
    enforce_scope("http://shop.test/x", {"shop.test"})  # in-scope: no raise


def test_prober_refuses_bad_method_pre_socket():
    opened = []
    p = HttpProber(opener=lambda req, timeout: opened.append(1))
    with pytest.raises(ScopeError):
        p.request("TRACE", "http://shop.test/")
    assert opened == []  # never touched the network


def test_prober_success():
    p = HttpProber(
        allowed_hosts={"shop.test"},
        opener=lambda req, timeout: FakeResp(200, [("Set-Cookie", "a=1")], b"ok"),
    )
    r = p.request("GET", "http://shop.test/")
    assert r.status == 200 and r.body_text == "ok" and r.set_cookie == ("a=1",)


def test_prober_httperror_becomes_probe():
    def opener(req, timeout):
        raise HTTPError("http://shop.test/", 403, "no", FakeHeaders([]), io.BytesIO(b"denied"))

    r = HttpProber(opener=opener).request("GET", "http://shop.test/")
    assert r.status == 403 and r.body_text == "denied"


def test_prober_urlerror_becomes_probe():
    def opener(req, timeout):
        raise URLError("boom")

    r = HttpProber(opener=opener).request("GET", "http://shop.test/")
    assert r.status is None and "boom" in r.error


# ---- cookie bisection -------------------------------------------------------

class FakeProber:
    def __init__(self, decide):
        self.decide = decide
        self.calls = []

    def request(self, method, url, *, headers=None, body=None):
        headers = headers or {}
        cookie = headers.get("Cookie", "")
        self.calls.append((method, url, cookie))
        status, body_text = self.decide(url, cookie)
        return Probe(method, url, status, {}, (), body_text)


def test_bisect_identifies_load_bearing_cookie():
    # auth holds iff the session id is present; theme/junk are placeholders.
    prober = FakeProber(lambda url, cookie: (200 if "sid=" in cookie else 401, ""))
    rep = S.bisect_cookies(prober, "http://shop.test/me", "sid=abc; theme=dark; junk=1")
    assert rep.alive is True
    assert rep.load_bearing == ("sid",)
    assert set(rep.placeholders) == {"theme", "junk"}


def test_bisect_reports_dead_session():
    prober = FakeProber(lambda url, cookie: (401, ""))
    rep = S.bisect_cookies(prober, "http://shop.test/me", "sid=abc")
    assert rep.alive is False and "cannot bisect" in rep.note


# ---- session-locked param mutation ------------------------------------------

def test_mutate_param_holds_cookie_and_varies_value():
    prober = FakeProber(lambda url, cookie: (200, url))
    res = S.mutate_param(
        prober, "http://shop.test/item?id=1", "id", ["2", "3"],
        cookie_header="sid=abc",
    )
    assert res.baseline.url == "http://shop.test/item?id=1"
    mutated_urls = [p.url for _v, p in res.mutations]
    assert "id=2" in mutated_urls[0] and "id=3" in mutated_urls[1]
    # cookie identical across every call
    assert {c for _m, _u, c in prober.calls} == {"sid=abc"}


def test_mutate_param_preserves_other_params():
    prober = FakeProber(lambda url, cookie: (200, url))
    res = S.mutate_param(prober, "http://shop.test/i?a=1&id=1", "id", ["9"])
    only = res.mutations[0][1].url
    assert "a=1" in only and "id=9" in only
