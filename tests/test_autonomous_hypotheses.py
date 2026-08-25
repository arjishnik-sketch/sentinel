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


# ---- pluggable providers (API-key models) ----------------------------------

def test_resolve_provider_defaults_to_offline_ollama():
    p = L.resolve_provider({})                       # empty env, no key needed
    assert p.name == "ollama"
    assert p.transport is L._ollama_json_chat


def test_resolve_provider_anthropic_binds_key_and_routes(monkeypatch):
    seen = {}

    def spy(system, user, *, model, url, timeout, num_predict, api_key):
        seen.update(model=model, url=url, api_key=api_key)
        return '{"ok": true}'

    monkeypatch.setattr(L, "_anthropic_json_chat", spy)
    p = L.resolve_provider(
        {"SENTINEL_LLM_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "sk-secret"}
    )
    assert p.name == "anthropic"
    assert p.model == "claude-sonnet-5"              # strong overridable default
    assert "api.anthropic.com" in p.url
    p.transport("s", "u", model=p.model, url=p.url, timeout=1, num_predict=8)
    assert seen["api_key"] == "sk-secret"            # key bound into transport
    assert "sk-secret" not in repr(p)                # ...and never leaked by repr


def test_resolve_provider_openai_binds_key_and_routes(monkeypatch):
    seen = {}

    def spy(system, user, *, model, url, timeout, num_predict, api_key):
        seen["api_key"] = api_key
        return "{}"

    monkeypatch.setattr(L, "_openai_json_chat", spy)
    p = L.resolve_provider(
        {"SENTINEL_LLM_PROVIDER": "openai", "OPENAI_API_KEY": "sk-oai"}
    )
    assert p.name == "openai" and p.model == "gpt-4o-mini"
    p.transport("s", "u", model=p.model, url=p.url, timeout=1, num_predict=8)
    assert seen["api_key"] == "sk-oai"


def test_resolve_provider_model_override_wins():
    p = L.resolve_provider(
        {
            "SENTINEL_LLM_PROVIDER": "anthropic",
            "ANTHROPIC_API_KEY": "sk-x",
            "SENTINEL_LLM_MODEL": "claude-opus-5",
        }
    )
    assert p.model == "claude-opus-5"


def test_resolve_provider_compatible_requires_base_url():
    import pytest

    with pytest.raises(L.LLMConfigError):
        L.resolve_provider({"SENTINEL_LLM_PROVIDER": "compatible"})


def test_resolve_provider_compatible_allows_keyless_gateway():
    p = L.resolve_provider(
        {"SENTINEL_LLM_PROVIDER": "compatible", "SENTINEL_LLM_URL": "http://gw.local/v1"}
    )
    assert p.name == "compatible" and p.url == "http://gw.local/v1"


def test_resolve_provider_missing_key_is_config_error_not_prompt():
    import pytest

    # No key, and pytest's stdin is not a TTY, so this must raise rather than
    # block on getpass. ask_json turns this into a non-fatal fallback.
    with pytest.raises(L.LLMConfigError):
        L.resolve_provider({"SENTINEL_LLM_PROVIDER": "anthropic"})


def test_resolve_provider_unknown_name_is_config_error():
    import pytest

    with pytest.raises(L.LLMConfigError):
        L.resolve_provider({"SENTINEL_LLM_PROVIDER": "totally-bogus"})


def test_ask_json_uses_resolved_provider_when_no_transport(monkeypatch):
    calls = {}

    def fake_transport(system, user, *, model, url, timeout, num_predict):
        calls.update(model=model, url=url)
        return '{"routed": true}'

    fake = L.LLMProvider(name="fake", transport=fake_transport, model="M", url="U")
    monkeypatch.setattr(L, "resolve_provider", lambda: fake)
    res = L.ask_json("s", "u")                        # no transport injected
    assert res.ok and res.data == {"routed": True}
    assert calls == {"model": "M", "url": "U"}        # provider's model/url used


def test_ask_json_config_error_is_nonfatal(monkeypatch):
    def boom():
        raise L.LLMConfigError("no key")

    monkeypatch.setattr(L, "resolve_provider", boom)
    res = L.ask_json("s", "u")
    assert res.ok is False and "no key" in res.error


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


def test_surface_emits_path_segment_endpoint_for_trailing_id():
    # A crawled URL with a concrete trailing resource id (…/users/1) yields a
    # SECOND endpoint at location="path" — the id-in-path SQLi surface — beside
    # the ordinary query endpoint. The param labels the resource segment before
    # the id ("users"); the URL is kept concrete (its own baseline anchor).
    s = Surface.from_recon(_recon(["http://shop.test/api/users/1"]), _findings())
    path_eps = [e for e in s.endpoints if e.location == "path"]
    assert len(path_eps) == 1
    assert path_eps[0].url == "http://shop.test/api/users/1"
    assert path_eps[0].params == ("users",)


def test_surface_ignores_non_id_trailing_segment():
    # An ordinary word segment (…/products/search) is NOT a resource id, so no
    # path endpoint is synthesised — only the plain query endpoint.
    s = Surface.from_recon(_recon(["http://shop.test/products/search"]), _findings())
    assert all(e.location != "path" for e in s.endpoints)


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


def test_rule_based_path_segment_emits_sqli_only():
    # A path-located endpoint (id in the URL path) yields exactly ONE hypothesis:
    # path-segment SQLi. The other injectable classes have no path placement, so
    # posing them here would be dishonest breadth.
    ep = Endpoint(url="http://shop.test/api/users/1", method="GET",
                  params=("users",), location="path")
    s = Surface(target="http://shop.test", endpoints=(ep,))
    hyps = H.rule_based_hypotheses(s)
    assert len(hyps) == 1
    assert hyps[0].technique == "sql_injection"
    assert hyps[0].location == "path"
    assert hyps[0].param == "users"
    assert hyps[0].provable is True


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
