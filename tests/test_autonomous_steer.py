"""Offline tests for OPERATOR STEER parsing (app.autonomous.steer).

Pure parsing — no network, no judges. Proves the operator is wired as a PROPOSER:
a suggestion becomes scope-guarded source="operator" Hypotheses (the pure judge
still disposes downstream), auth context is captured without ever confirming
anything, and malformed input degrades to `ignored` instead of crashing.
"""
from app.autonomous import steer as ST
from app.autonomous.surface import Surface


def _surface(target="http://shop.test"):
    return Surface(target=target)


def test_add_verb_line_becomes_operator_hypothesis():
    d = ST.parse_operator_suggestion(
        "test sqli http://shop.test/item?id=1 id body_json HIGH", _surface())
    assert len(d.hypotheses) == 1
    h = d.hypotheses[0]
    assert h.technique == "sql_injection" and h.source == "operator"
    assert h.url == "http://shop.test/item?id=1" and h.param == "id"
    assert h.location == "body_json" and h.severity == "HIGH"


def test_bare_form_without_verb_and_alias_mapping():
    d = ST.parse_operator_suggestion("xss http://shop.test/s?q=1 q", _surface())
    assert [h.technique for h in d.hypotheses] == ["xss"]
    assert d.hypotheses[0].param == "q" and d.hypotheses[0].location == "query"


def test_relative_path_is_absolutized_against_target_origin():
    d = ST.parse_operator_suggestion("test sql_injection /rest/user/login email",
                                     _surface("http://shop.test:3000"))
    assert d.hypotheses[0].url == "http://shop.test:3000/rest/user/login"
    assert d.hypotheses[0].param == "email"


def test_off_host_proposal_is_scope_rejected():
    d = ST.parse_operator_suggestion("test sqli http://evil.test/x?id=1 id", _surface())
    assert d.hypotheses == ()
    assert d.ignored and "evil.test" in d.ignored[0]


def test_unknown_technique_is_ignored_not_crash():
    d = ST.parse_operator_suggestion("test wizardry http://shop.test/x q", _surface())
    assert d.hypotheses == () and d.ignored == ("test wizardry http://shop.test/x q",)


def test_token_line_captures_bearer_and_strips_prefix():
    d = ST.parse_operator_suggestion("token Bearer eyJhbGciOi.J.K", _surface())
    assert d.token == "eyJhbGciOi.J.K"
    assert d.hypotheses == ()               # a token is auth context, not a hypothesis
    assert d.has_auth_context and not d.is_empty


def test_matrix_line_captures_path_unquoted():
    d = ST.parse_operator_suggestion('matrix "C:\\policies\\authz.json"', _surface())
    assert d.matrix_path == "C:\\policies\\authz.json"
    assert d.has_auth_context


def test_comments_blank_and_continue_words_are_skipped():
    text = "\n# a note\n\ngo\ndone\ncontinue\n"
    d = ST.parse_operator_suggestion(text, _surface())
    assert d.is_empty and d.ignored == ()


def test_dedup_within_a_single_suggestion():
    text = ("test sqli http://shop.test/item?id=1 id\n"
            "sqli http://shop.test/item?id=1 id query")   # same key
    d = ST.parse_operator_suggestion(text, _surface())
    assert len(d.hypotheses) == 1


def test_multi_line_mixes_hypotheses_and_auth_context():
    text = ("test sqli http://shop.test/a?id=1 id\n"
            "token eyJ.a.b\n"
            "matrix /tmp/m.json\n"
            "xss http://shop.test/b?q=1 q\n"
            "garbage line here")
    d = ST.parse_operator_suggestion(text, _surface())
    assert {h.technique for h in d.hypotheses} == {"sql_injection", "xss"}
    assert d.token == "eyJ.a.b" and d.matrix_path == "/tmp/m.json"
    assert d.ignored == ("garbage line here",)


def test_empty_and_none_input_are_empty_directives():
    assert ST.parse_operator_suggestion("", _surface()).is_empty
    assert ST.parse_operator_suggestion(None, _surface()).is_empty
