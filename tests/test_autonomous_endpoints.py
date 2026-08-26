"""Offline tests for Stage 2 SELECT ENDPOINTS (app.autonomous.endpoints).

Pure data — no network. Proves the injectability ranking is deterministic and
that pruning is opt-in (budget) and honest (full coverage by default).
"""
from app.autonomous.endpoints import select_endpoints, EndpointScore, EndpointSelection
from app.autonomous.surface import Surface, Endpoint


def _surface(*endpoints):
    return Surface(target="http://shop.test", endpoints=tuple(endpoints))


def test_empty_surface_is_empty_selection():
    sel = select_endpoints(_surface())
    assert sel.total == 0 and sel.endpoints == () and not sel.pruned


def test_ranks_by_injectability_and_is_deterministic():
    bare = Endpoint("http://shop.test/about", "GET", (), "query")
    one = Endpoint("http://shop.test/item?x=1", "GET", ("x",), "query")
    rich = Endpoint("http://shop.test/search?q=a&id=1&url=z", "GET",
                    ("q", "id", "url"), "query")
    sel = select_endpoints(_surface(bare, one, rich))
    ranked = [s.endpoint.url for s in sel.scored]
    # rich (search+id+redirect+params) > one (single param) > bare (no signal)
    assert ranked[0] == rich.url and ranked[-1] == bare.url
    # deterministic: same surface → identical ranking
    again = select_endpoints(_surface(bare, one, rich))
    assert [s.endpoint.url for s in again.scored] == ranked
    assert all(isinstance(s, EndpointScore) for s in sel.scored)


def test_no_budget_keeps_full_coverage():
    a = Endpoint("http://shop.test/a?id=1", "GET", ("id",), "query")
    b = Endpoint("http://shop.test/b", "GET", (), "query")
    sel = select_endpoints(_surface(a, b))
    assert sel.total == 2
    assert set(e.url for e in sel.endpoints) == {a.url, b.url}   # nothing dropped
    assert not sel.pruned and sel.dropped == ()


def test_budget_prunes_tail_only_keeping_top_scored():
    high = Endpoint("http://shop.test/s?q=a&id=1", "GET", ("q", "id"), "query")
    low = Endpoint("http://shop.test/plain", "GET", (), "query")
    sel = select_endpoints(_surface(low, high), budget=1)
    assert sel.pruned
    assert [e.url for e in sel.endpoints] == [high.url]          # kept the injectable one
    assert [s.endpoint.url for s in sel.dropped] == [low.url]


def test_budget_zero_or_negative_is_rank_only():
    a = Endpoint("http://shop.test/a?id=1", "GET", ("id",), "query")
    b = Endpoint("http://shop.test/b", "GET", (), "query")
    for budget in (0, -3):
        sel = select_endpoints(_surface(a, b), budget=budget)
        assert not sel.pruned and len(sel.endpoints) == 2


def test_path_id_endpoint_outranks_bare_page():
    path_id = Endpoint("http://shop.test/users/1", "GET", ("users",), "path")
    bare = Endpoint("http://shop.test/home", "GET", (), "query")
    sel = select_endpoints(_surface(bare, path_id))
    assert sel.scored[0].endpoint.location == "path"
    assert any("path-segment" in r for r in sel.scored[0].reasons)


def test_high_value_param_names_score_and_explain():
    ep = Endpoint("http://shop.test/x?q=a&id=1&next=/z&file=p", "GET",
                  ("q", "id", "next", "file"), "query")
    score = select_endpoints(_surface(ep)).scored[0]
    joined = ", ".join(score.reasons)
    assert "search param 'q'" in joined
    assert "id-like param 'id'" in joined
    assert "redirect-shaped param 'next'" in joined
    assert "file/path param 'file'" in joined


def test_auth_and_api_paths_boost_score():
    plain = Endpoint("http://shop.test/x?u=1", "GET", ("u",), "query")
    auth = Endpoint("http://shop.test/rest/user/login?u=1", "GET", ("u",), "query")
    sel = select_endpoints(_surface(plain, auth))
    top, bottom = sel.scored[0], sel.scored[1]
    assert top.endpoint.url == auth.url and top.score > bottom.score
    assert any("auth-adjacent" in r for r in top.reasons)
    assert any("api-shaped" in r for r in top.reasons)


def test_selection_is_a_frozen_data_object():
    sel = select_endpoints(_surface(Endpoint("http://shop.test/a", "GET", (), "query")))
    assert isinstance(sel, EndpointSelection)
    # kept/dropped/endpoints are derived views, never mutate the scored tuple
    assert sel.kept == sel.scored and sel.endpoints == (sel.scored[0].endpoint,)
