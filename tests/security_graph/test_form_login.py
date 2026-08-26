"""Offline, network-free proof of the headless HTTP form-login capture
(app.security_graph.session.form_login).

Sentinel captures a genuine session token FROM credentials without any external
driver: fetch the login page, parse its <form>, POST the credentials through a
cookie jar, and read the token off the response. This whole path is pure given an
injected HTTP client seam, so every test here runs with zero network.

The password fills the live form only; the captured token surfaces as PRESENCE in
a token-safe note, never as a value. These tests assert both the mechanics and
that secret-safety contract. Nothing decides a verdict — capture produces an
OBSERVATION the pure judge tests later.
"""

import pytest

from app.security_graph.session.form_login import (
    CredentialSession,
    LoginCaptureError,
    LoginForm,
    _choose_username_field,
    _extract_bearer_from_body,
    capture_login_session,
    find_login_form,
)
from app.security_graph.broken_auth.broken_auth_policy import TokenLocation


# ---- fakes: an injectable HTTP client seam (no sockets) ---------------------


class FakeResponse:
    def __init__(self, text="", url=""):
        self.text = text
        self.url = url


class FakeClient:
    """Records issued requests; serves canned pages and a canned cookie jar."""

    def __init__(self, pages=None, post_response=None, cookies=None):
        self._pages = pages or {}
        self._post_response = post_response or FakeResponse()
        self._cookies = dict(cookies or {})
        self.calls = []

    def get(self, url):
        self.calls.append(("GET", url, None))
        return self._pages.get(url, FakeResponse(url=url))

    def post(self, url, data):
        self.calls.append(("POST", url, data))
        return self._post_response

    @property
    def cookies(self):
        return dict(self._cookies)


_LOGIN_HTML = """
<html><body>
  <form action="/login" method="POST">
    <input type="hidden" name="csrf" value="tok123">
    <input type="text" name="username">
    <input type="password" name="password">
    <button type="submit">Go</button>
  </form>
</body></html>
"""


# ---- pure: form discovery ---------------------------------------------------


def test_find_login_form_picks_password_form_and_carries_hidden_fields():
    form = find_login_form(_LOGIN_HTML, "http://shop.test/login")
    assert form is not None
    assert form.action == "http://shop.test/login"
    assert form.method == "POST"
    assert form.username_field == "username"
    assert form.password_field == "password"
    # every OTHER named field is carried verbatim (the CSRF token), and neither
    # credential field pre-populates data
    assert form.data == {"csrf": "tok123"}


def test_find_login_form_returns_none_without_password_field():
    html = '<form action="/x"><input name="q" type="text"></form>'
    assert find_login_form(html, "http://shop.test/x") is None


def test_find_login_form_absolutizes_relative_action():
    html = '<form action="do/login" method="post"><input type="password" name="p"></form>'
    form = find_login_form(html, "http://shop.test/auth/")
    assert form.action == "http://shop.test/auth/do/login"
    assert form.method == "POST"


def test_payload_merges_carried_fields_and_credentials():
    form = LoginForm(action="http://x/login", data={"csrf": "z"},
                     username_field="user", password_field="pass")
    body = form.payload("wiener", "peter")
    assert body == {"csrf": "z", "user": "wiener", "pass": "peter"}


def test_choose_username_field_prefers_email_then_hint_then_preceding():
    email = [{"name": "e", "type": "email", "value": ""},
             {"name": "p", "type": "password", "value": ""}]
    assert _choose_username_field(email, 1) == "e"

    hint = [{"name": "login_id", "type": "text", "value": ""},
            {"name": "p", "type": "password", "value": ""}]
    assert _choose_username_field(hint, 1) == "login_id"

    preceding = [{"name": "first", "type": "text", "value": ""},
                 {"name": "p", "type": "password", "value": ""}]
    assert _choose_username_field(preceding, 1) == "first"


def test_choose_username_field_handles_portswigger_type_username():
    # PortSwigger's login form uses the NON-standard `type=username`; the field
    # must still be chosen (its name hints "user"), never silently dropped, or the
    # POST goes out with no username and the login fails.
    inputs = [{"name": "csrf", "type": "hidden", "value": "tok"},
              {"name": "username", "type": "username", "value": ""},
              {"name": "password", "type": "password", "value": ""}]
    assert _choose_username_field(inputs, 2) == "username"


def test_find_login_form_reads_portswigger_shape_with_csrf_and_type_username():
    html = (
        '<form class=login-form method=POST action="/login">'
        '<input required type="hidden" name="csrf" value="ABQmoir">'
        '<input required type=username name="username" autofocus>'
        '<input required type=password name="password">'
        "</form>"
    )
    form = find_login_form(html, "http://lab.test/login")
    assert form is not None
    assert form.username_field == "username"
    assert form.password_field == "password"
    assert form.data == {"csrf": "ABQmoir"}
    body = form.payload("wiener", "peter")
    assert body == {"csrf": "ABQmoir", "username": "wiener", "password": "peter"}


# ---- pure: bearer extraction from a JSON body -------------------------------


def test_extract_bearer_reads_token_key_and_strips_prefix():
    assert _extract_bearer_from_body('{"token": "Bearer eyJ.a.b"}') == "eyJ.a.b"
    assert _extract_bearer_from_body('{"data": {"access_token": "xyz"}}') == "xyz"


def test_extract_bearer_none_for_non_json_or_missing_key():
    assert _extract_bearer_from_body("<html>not json</html>") is None
    assert _extract_bearer_from_body('{"unrelated": "value"}') is None


# ---- pure: token_for honors the declared location ---------------------------


def test_token_for_cookie_location_returns_named_cookie():
    session = CredentialSession(cookies=(("session", "COOK1"), ("other", "x")))
    loc = TokenLocation(kind="cookie", name="session")
    assert session.token_for(loc) == "COOK1"


def test_token_for_header_location_prefers_bearer():
    session = CredentialSession(cookies=(("session", "COOK1"),), bearer="BEAR1")
    assert session.token_for(TokenLocation(kind="header")) == "BEAR1"


def test_token_for_falls_back_to_session_like_cookie():
    # header location, no bearer captured -> any session-like cookie serves
    session = CredentialSession(cookies=(("session", "COOK1"),))
    assert session.token_for(TokenLocation(kind="header")) == "COOK1"


def test_token_for_none_when_nothing_captured():
    session = CredentialSession(cookies=(("cookieconsent", "yes"),))
    assert session.token_for(TokenLocation(kind="cookie", name="session")) is None


def test_capture_note_is_presence_only_never_a_value():
    from app.security_graph.session.form_login import _capture_note

    note = _capture_note((("session", "SECRET"),), "SECRET2")
    assert "SECRET" not in note and "SECRET2" not in note
    assert "cookie" in note and "bearer" in note


# ---- driver: capture_login_session with an injected client ------------------


def test_capture_login_session_posts_credentials_and_captures_cookie():
    client = FakeClient(
        pages={"http://shop.test/login": FakeResponse(_LOGIN_HTML,
                                                       "http://shop.test/login")},
        post_response=FakeResponse("welcome", "http://shop.test/my-account"),
        cookies={"session": "CAPTURED-COOKIE"},
    )
    session = capture_login_session(
        "http://shop.test/login", username="wiener", password="peter", http=client)

    # the POST carried the CSRF token + both credentials to the form action
    post = [c for c in client.calls if c[0] == "POST"][0]
    assert post[1] == "http://shop.test/login"
    assert post[2] == {"csrf": "tok123", "username": "wiener", "password": "peter"}

    assert ("session", "CAPTURED-COOKIE") in session.cookies
    loc = TokenLocation(kind="cookie", name="session")
    assert session.token_for(loc) == "CAPTURED-COOKIE"
    # the note reports presence only
    assert "CAPTURED-COOKIE" not in session.note


def test_capture_login_session_reads_bearer_from_json_body():
    client = FakeClient(
        pages={"http://api.test/login": FakeResponse(_LOGIN_HTML,
                                                     "http://api.test/login")},
        post_response=FakeResponse('{"access_token": "JWT.X.Y"}',
                                   "http://api.test/home"),
        cookies={},
    )
    session = capture_login_session(
        "http://api.test/login", username="u", password="p", http=client)
    assert session.bearer == "JWT.X.Y"
    assert session.token_for(TokenLocation(kind="header")) == "JWT.X.Y"


def test_capture_login_session_raises_when_no_form_found():
    client = FakeClient(
        pages={"http://shop.test/login": FakeResponse("<html>no form</html>",
                                                      "http://shop.test/login")},
    )
    with pytest.raises(LoginCaptureError):
        capture_login_session("http://shop.test/login",
                              username="u", password="p", http=client)


def test_capture_login_session_requires_a_login_url_or_target():
    with pytest.raises(LoginCaptureError):
        capture_login_session("", username="u", password="p", http=FakeClient())


def test_capture_login_session_derives_login_url_from_target():
    client = FakeClient(
        pages={"http://shop.test/login": FakeResponse(_LOGIN_HTML,
                                                      "http://shop.test/login")},
        post_response=FakeResponse("ok", "http://shop.test/account"),
        cookies={"session": "C"},
    )
    session = capture_login_session(
        "", username="u", password="p", http=client, target="http://shop.test")
    assert session.token_for(TokenLocation(kind="cookie", name="session")) == "C"


# ---- live client scope guard (constructed, but no network issued) -----------


def test_requests_client_refuses_out_of_scope_host():
    from app.security_graph.session.form_login import _RequestsClient

    client = _RequestsClient(allowed_host="shop.test")
    with pytest.raises(LoginCaptureError):
        client.get("http://evil.test/login")


def test_requests_client_refuses_non_http_scheme():
    from app.security_graph.session.form_login import _RequestsClient

    client = _RequestsClient(allowed_host="shop.test")
    with pytest.raises(LoginCaptureError):
        client.get("file:///etc/passwd")
