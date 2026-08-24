"""Offline tests for the autonomous hypothesis stack (no Ollama, no network)."""
from app.autonomous import llm as L
from app.autonomous.surface import Surface, Endpoint
from app.autonomous import hypotheses as H


def _transport_ok(payload):
    def t(system, user, *, model, url, timeout, num_predict):
        return payload
    return t


# ---- LLM client -------------------------------------------------------------

def test_ask_json_parses_clean_json():
    res = L.ask_json("s", "u", transport=_transport_ok('{"a": 1}'))
    assert res.ok and res.data == {"a": 1}


def test_ask_json_lenient_extracts_embedded_json():
    res = L.ask_json("s", "u", transport=_transport_ok('sure!\n{"x": [1,2]}\ndone'))
    assert res.ok and res.data == {"x": [1, 2]}


def test_ask_json_transport_error_is_nonfatal():
    def boom(*a, **k):
        raise RuntimeError("ollama down")

    res = L.ask_json("s", "u", transport=boom)
    assert res.ok is False and res.data is None and "ollama down" in res.error


def test_ask_json_unparseable():
    res = L.ask_json("s", "u", transport=_transport_ok("not json at all"))
    assert res.ok is False


# ---- surface ----------------------------------------------------------------

def _recon(crawl, tech=()):
    return {"target": "http://shop.test", "crawl": crawl, "alive": [{"tech": list(tech)}]}


def _findings(**kw):
    base = {
        "parameters": [], "logins": [], "javascript": [], "graphql": [],
        "swagger": [], "uploads": [], "apis": [],
    }
    base.update(kw)
    return base


def test_surface_extracts_params_and_flags():
    s = Surface.from_recon(
        _recon(["http://shop.test/item?id=1&q=x"]),
        _findings(parameters=["id", "q"], logins=["http://shop.test/login"]),
    )
    assert s.host == "shop.test"
    assert s.has_login is True
    ep = s.endpoints[0]
    assert ep.params == ("id", "q")


def test_surface_spa_detection_by_tech():
    s = Surface.from_recon(_recon(["http://shop.test/"], tech=["React"]), _findings())
    assert s.is_spa is True


# ---- hypotheses -------------------------------------------------------------

def _surface_with_param(param="id"):
    ep = Endpoint(url="http://shop.test/item", method="GET", params=(param,), location="query")
    return Surface(target="http://shop.test", endpoints=(ep,))


def test_rule_based_covers_injectable_param():
    hyps = H.rule_based_hypotheses(_surface_with_param())
    techs = {h.technique for h in hyps}
    assert {"sql_injection", "xss", "path_traversal"} <= techs


def test_rule_based_redirect_param():
    hyps = H.rule_based_hypotheses(_surface_with_param("returnUrl"))
    assert any(h.technique == "open_redirect" for h in hyps)


def test_rule_based_login_broken_auth():
    s = Surface(target="http://shop.test", logins=("http://shop.test/login",), has_login=True)
    assert any(h.technique == "broken_auth" for h in H.rule_based_hypotheses(s))


def test_parse_drops_unknown_and_offhost():
    s = _surface_with_param()
    data = {"hypotheses": [
        {"technique": "sql_injection", "url": "http://shop.test/x", "param": "id"},
        {"technique": "made_up", "url": "http://shop.test/y"},
        {"technique": "xss", "url": "http://evil.com/z"},
    ]}
    parsed = H.parse_hypotheses(data, s)
    assert len(parsed) == 1 and parsed[0].technique == "sql_injection"
    assert parsed[0].source == "llm"


def test_propose_merges_llm_breadth_over_rule_floor():
    s = _surface_with_param()
    payload = '{"hypotheses":[{"technique":"ssrf","url":"http://shop.test/item","param":"id","location":"query"}]}'
    hyps = H.propose(s, transport=_transport_ok(payload))
    techs = {h.technique for h in hyps}
    assert "ssrf" in techs                      # LLM added breadth
    assert "sql_injection" in techs             # rule floor preserved


def test_propose_no_llm_is_rules_only():
    s = _surface_with_param()
    hyps = H.propose(s, use_llm=False)
    assert hyps and all(h.source == "rule" for h in hyps)


def test_routing_provable_flag():
    assert H.Hypothesis("sql_injection", "u").provable is True
    assert H.Hypothesis("graphql_introspection", "u").provable is False
