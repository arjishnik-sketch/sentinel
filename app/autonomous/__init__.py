"""The fused autonomous pentest loop.

DISCOVER (real recon tools + fingerprint) -> UNDERSTAND (skills KB) ->
HYPOTHESIZE (qwen proposes) -> EXECUTE (concurrent, session-aware, auto-install
tools on approval) -> PROVE (the existing pure deterministic judges) ->
PATCH -> PROVE.

The one rule that never bends: the LLM and the tools only PROPOSE; a
deterministic judge disposes. A CONFIRMED finding always comes from a pure
judge reproducing a differential, never from a bare status code or an LLM.
"""
