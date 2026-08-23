"""
`discover <target>` — zero-oracle autonomous discovery.

This is the "point Sentinel at a URL and it finds the bugs" entry point. It is a
thin wrapper over :func:`app.commands.investigate_cmd.run` with
``discover_mode=True``: the client supplies ONLY a URL (an optional cycle budget
may follow) — no operator-authored policy, matrix, or oracle.

Why this stays honest (the epistemic contract is fully preserved):

  * Header + cookie posture already run zero-config off Sentinel's built-in
    secure baseline, so those two classes never needed an operator.
  * SQL injection is the flagship discoverable class because its ground truth is
    *internal*: the three-way boolean differential (a benign baseline plus
    length-matched TRUE/FALSE payload pairs) is self-anchoring. The operator only
    ever had to say *where to look* — and live reconnaissance observed that for
    us. In discover mode the injectable surface is SYNTHESIZED from recon
    (observed query parameters + a fixed, target-agnostic generic-parameter list
    on query-surface endpoints) and every synthesized candidate is decided by the
    SAME pure judge. A parameter the backend ignores collapses (TRUE == FALSE) →
    DISPROVED → no finding. Nothing is manufactured.

Authorization / privilege-escalation intent cannot be inferred from a bare URL,
so those classes still require a declared matrix; they simply skip here (their
attack surface is still surfaced as honest leads by the research loop). Pass a
policy file to ``investigate`` to prove them.
"""

from app.commands.investigate_cmd import run as _investigate_run


def run(arg):
    """Dispatch to the shared research pipeline in discover mode."""
    if not arg or not arg.strip():
        from app.commands.investigate_cmd import console, _C_BAD

        console.print(
            f"[{_C_BAD}]Usage:[/{_C_BAD}] discover <target> [cycles]\n"
            f"[dim]e.g. discover http://127.0.0.1:3000[/dim]\n"
            f"[dim]no policy needed — Sentinel derives its own injectable "
            f"surface from live recon and proves it with the pure boolean "
            f"differential; header + cookie posture run off the secure "
            f"baseline[/dim]"
        )
        return

    return _investigate_run(arg, discover_mode=True)
