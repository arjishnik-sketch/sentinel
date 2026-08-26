"""The fused autonomous pentest loop.

DISCOVER (real recon tools + fingerprint) -> UNDERSTAND (skills KB) ->
HYPOTHESIZE (qwen proposes over a deterministic rule floor) -> EXECUTE
(concurrent, optional session-aware stage) -> PROVE (the existing pure
deterministic judges) -> REFINE (failure-cause analysis re-poses a non-terminal
verdict with a different probe shape and re-judges it) -> PATCH -> PROVE ->
REPORT (proof-carrying markdown+json).

EXECUTE is now a bounded adaptive loop, not a single forward pass: an
INCONCLUSIVE/ERROR verdict is diagnosed (app.autonomous.refine) and retried with
a mutated hypothesis, and the pure judge disposes each variant independently. The
curated tool-selector (app.tools) is not yet wired into EXECUTE, so no external
exploitation tool runs here yet — that remains on the roadmap.

The one rule that never bends: the LLM and the tools only PROPOSE — and a retry
is only ever another proposal; a deterministic judge disposes. A CONFIRMED
finding always comes from a pure judge reproducing a differential, never from a
bare status code, an LLM, or the fact that a retry was attempted.
"""
