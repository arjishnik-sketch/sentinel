"""
Offline proof of the OpenAPI/Swagger → CANDIDATE policy importer.

The importer translates ONLY the spec's explicitly DECLARED authorization intent
(each operation's `security` requirement) and never infers a security decision:

  * an operation requiring a non-empty scheme      → candidate anonymous DENY;
  * an operation with an explicit `security: []`    → candidate anonymous ALLOW;
  * an operation that is silent (and no global)     → NO rule (never guessed).

Every emitted document is a CANDIDATE the operator confirms, and it must itself
parse cleanly through the real oracle loaders — proven here without any network.
"""

import json

import pytest

from app.security_graph.cookies.cookie_policy import parse_cookie_policy
from app.security_graph.policy.access_policy import parse_access_policy
from app.security_graph.posture.header_policy import parse_header_policy
from app.security_graph.spec_import import build_candidate_policy, import_spec_file


def _rule_for(document, decision, path):
    return [
        r for r in document.get("rules", [])
        if r["decision"] == decision and r["path"] == path
    ]


def _openapi3():
    return {
        "openapi": "3.0.3",
        "servers": [{"url": "https://api.example.test/v2"}],
        "paths": {
            "/private": {
                "get": {
                    "operationId": "getPrivate",
                    "security": [{"apiKey": []}],
                }
            },
            "/public": {
                "get": {"operationId": "getPublic", "security": []}
            },
            "/silent": {
                "get": {"operationId": "getSilent"}  # no declaration
            },
        },
    }


# --- declared intent → candidate rules --------------------------------------

def test_openapi3_declared_intent_becomes_candidate_rules():
    document, summary = build_candidate_policy(_openapi3())

    assert summary.spec_kind == "OpenAPI 3.x"
    assert summary.base_path == "/v2"
    assert summary.total_operations == 3
    assert summary.deny_candidates == 1
    assert summary.allow_candidates == 1
    assert summary.silent_operations == 1

    # base path is prepended so candidate paths match the live target
    assert _rule_for(document, "deny", "/v2/private")
    assert _rule_for(document, "allow", "/v2/public")
    # a silent operation is never translated into a rule
    assert not _rule_for(document, "deny", "/v2/silent")
    assert not _rule_for(document, "allow", "/v2/silent")

    # every rule targets the anonymous principal and is a candidate
    assert document["candidate"] is True
    assert all(r["principal"] == "anonymous" for r in document["rules"])
    assert all("CANDIDATE" in r["note"] for r in document["rules"])


def test_global_security_default_applies_only_when_operation_silent():
    spec = {
        "openapi": "3.0.0",
        "security": [{"apiKey": []}],  # global default: auth required
        "paths": {
            "/inherits": {"get": {"operationId": "a"}},          # → deny
            "/overrides": {"get": {"operationId": "b", "security": []}},  # allow
        },
    }
    document, summary = build_candidate_policy(spec)
    assert summary.deny_candidates == 1
    assert summary.allow_candidates == 1
    assert _rule_for(document, "deny", "/inherits")
    assert _rule_for(document, "allow", "/overrides")


def test_swagger2_detection_and_base_path():
    spec = {
        "swagger": "2.0",
        "basePath": "/api",
        "paths": {
            "/users": {
                "get": {"operationId": "listUsers", "security": [{"oauth": []}]}
            }
        },
    }
    document, summary = build_candidate_policy(spec)
    assert summary.spec_kind == "Swagger 2.0"
    assert summary.base_path == "/api"
    assert _rule_for(document, "deny", "/api/users")


# --- honest degenerate + error paths ----------------------------------------

def test_degenerate_spec_has_no_rules_but_keeps_baseline():
    spec = {
        "openapi": "3.1.0",
        "paths": {"/anything": {"get": {"operationId": "x"}}},  # all silent
    }
    document, summary = build_candidate_policy(spec)
    assert summary.deny_candidates == 0 and summary.allow_candidates == 0
    assert "rules" not in document  # nothing to translate → omit it honestly
    assert document["header_rules"] and document["cookie_rules"]


def test_unrecognised_document_raises():
    with pytest.raises(ValueError):
        build_candidate_policy({"paths": {}})


# --- the emitted candidate must load through the real oracle parsers ---------

def test_import_spec_file_json_round_trips_through_oracle(tmp_path):
    spec_file = tmp_path / "api.openapi.json"
    spec_file.write_text(json.dumps(_openapi3()), encoding="utf-8")

    document, summary = import_spec_file(spec_file)

    # import_spec_file already validates internally; assert it explicitly too.
    parse_access_policy(document)
    parse_header_policy(document)
    parse_cookie_policy(document)
    assert summary.spec_kind == "OpenAPI 3.x"


def test_import_spec_file_reads_yaml(tmp_path):
    pytest.importorskip("yaml")
    yaml_text = (
        "swagger: '2.0'\n"
        "basePath: /api\n"
        "paths:\n"
        "  /secure:\n"
        "    get:\n"
        "      operationId: s\n"
        "      security:\n"
        "        - key: []\n"
    )
    spec_file = tmp_path / "api.swagger.yaml"
    spec_file.write_text(yaml_text, encoding="utf-8")

    document, summary = import_spec_file(spec_file)
    assert summary.spec_kind == "Swagger 2.0"
    assert _rule_for(document, "deny", "/api/secure")
