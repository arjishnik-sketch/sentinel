"""
Consume a typed artifact as the next class's probe input — a pure mapping.

The composer keeps ALL verdict logic inside each class's own run/judge. This
module only performs the mechanical substitution of a leaked value into a
downstream probe template, plus the derivation of a same-shaped **decoy** value
used to prove the edge is load-bearing (see the decoy test in
:mod:`app.security_graph.chaining.compose`).
"""

from __future__ import annotations


DEFAULT_PLACEHOLDER = "{id}"


def inject_artifact(
    template: str,
    artifact_value: str,
    *,
    placeholder: str = DEFAULT_PLACEHOLDER,
) -> str:
    """
    Substitute a leaked value into a downstream probe template.

    Pure and target-agnostic: the value goes exactly where the operator's chain
    target says the identifier belongs (e.g. ``/rest/basket/{id}``).
    """
    return template.replace(placeholder, str(artifact_value))


def decoy_value(value: str) -> str:
    """
    A same-shaped but guaranteed-different value for the decoy test.

    Digits rotate by 5 (``d != (d+5) % 10`` for every digit) and letters rotate
    by 13 (rot13 never fixes a letter), so any value with at least one
    alphanumeric character yields a distinct string of the same length and
    character classes. This preserves "shape" (so a route that answers for *any*
    id of that shape will also answer for the decoy — collapsing the edge) while
    guaranteeing it is not the real leaked id.
    """
    if not value:
        return "0"

    chars: list[str] = []
    changed = False
    for ch in value:
        if ch.isdigit():
            rotated = str((int(ch) + 5) % 10)
        elif ch.isalpha():
            base = ord("a") if ch.islower() else ord("A")
            rotated = chr((ord(ch) - base + 13) % 26 + base)
        else:
            rotated = ch
        if rotated != ch:
            changed = True
        chars.append(rotated)

    out = "".join(chars)
    if not changed or out == value:
        # Pure-symbol / symmetric edge case: force a difference without inflating
        # length unboundedly.
        tail = out[-1:]
        if tail.isdigit():
            out = out[:-1] + ("1" if tail != "1" else "2")
        else:
            out = out + "0"
    return out
