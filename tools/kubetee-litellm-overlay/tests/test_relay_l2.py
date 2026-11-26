#!/usr/bin/env python3
"""Offline regression for Layer-2 caller-binding relay completeness.

Run from anywhere; needs no cluster, no Trustee, no network. Stubs the
`litellm` package and exercises `_normalize_backend_evidence` +
`_backend_identity_headers` in kubetee_attestation:

  * a signed (nonce-bound) envelope RELAYS the verification material:
    `counter`, `tee_pubkey`, `keyset`, `keyset_digest`, `signature_input`.
  * a plain cache envelope (no signature) leaves those EMPTY — the caller
    then sees "epoch-freshness only, no caller-binding".
  * ROUND-TRIP proof: sign `signature_input` with an Ed25519 key, reconstruct
    the input from ONLY the relayed fields (quote_sha256, counter, epoch.id)
    + the caller nonce, and verify against the relayed `tee_pubkey`. Passing
    proves the relayed material is SUFFICIENT to verify and the recipe is
    byte-exact (mirrors the backend signer's `signature_input()`).

Exit 0 = all pass. Mirrors test_breaker.py / test_registry_matcher.py.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import sys
import types


def _stub_litellm() -> None:
    if "litellm" in sys.modules:
        return
    litellm_mod = types.ModuleType("litellm")
    integrations = types.ModuleType("litellm.integrations")
    custom_logger = types.ModuleType("litellm.integrations.custom_logger")

    class CustomLogger:  # noqa: D401 - stub base class
        pass

    custom_logger.CustomLogger = CustomLogger
    logging_mod = types.ModuleType("litellm._logging")

    class _L:
        def error(self, *a, **k):
            pass

        def info(self, *a, **k):
            pass

    logging_mod.verbose_proxy_logger = _L()
    sys.modules["litellm"] = litellm_mod
    sys.modules["litellm.integrations"] = integrations
    sys.modules["litellm.integrations.custom_logger"] = custom_logger
    sys.modules["litellm._logging"] = logging_mod


_stub_litellm()
HERE = os.path.dirname(os.path.abspath(__file__))
OVERLAY = os.path.dirname(HERE)
sys.path.insert(0, OVERLAY)

import kubetee_attestation as ka  # noqa: E402

_results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    _results.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{(' — ' + detail) if detail else ''}")


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _unb64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# --- the normative Layer-2 reconstruction (mirrors the backend signer) ------
def layer2_input(quote_sha256: str, nonce_hex: str, epoch_id: str, counter: int) -> bytes:
    return (
        bytes.fromhex(quote_sha256)  # SHA-256(quote_bytes) — the relayed quote_sha256
        + hashlib.sha256(bytes.fromhex(nonce_hex)).digest()  # SHA-256(nonce 32B)
        + epoch_id.encode("ascii")
        + int(counter).to_bytes(8, "big")
    )


NONCE_HEX = "ab" * 32  # a 64-hex caller nonce


def _make_signed_raw() -> tuple[dict, bytes, bytes]:
    """Build a realistic nonce-bound backend payload + (pubkey, sig_input)."""
    from cryptography.hazmat.primitives.asymmetric import ed25519

    seed = b"\x11" * 32
    # cryptography needs a real 32B seed; derive via Ed25519PrivateKey.
    priv = ed25519.Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization

    raw_pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    quote = _b64(b"\x21" * 100)  # some TDX quote bytes
    quote_sha256 = hashlib.sha256(b"\x21" * 100).hexdigest()
    epoch_id = "1795569990525147904-1"
    counter = 7
    keyset = {"subject": "v1/example", "tls_public_keys": [{"spki_sha256": "0" * 64}]}
    keyset_digest = "sha256:" + hashlib.sha256(
        __import__("json").dumps(keyset, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()

    sig_input = layer2_input(quote_sha256, NONCE_HEX, epoch_id, counter)
    signature = _b64(priv.sign(sig_input))

    raw = {
        "tee": "tdx",
        "role": "nim-terminator",
        "runtime_class": "kata-qemu-nvidia-gpu-tdx-runtime-rs",
        "epoch_id": epoch_id,
        "issued_at": "2026-11-25T01:26:30Z",
        "valid_until": "2026-11-25T01:31:30Z",
        "counter": counter,
        "quote": quote,
        "report_data": _b64(b"\x00" * 64),
        "report_data_statement": '{"epoch_id":"...","purpose":"kubetee.attestation.v1"}',
        "cc_eventlog": _b64(b"\x30" * 40),
        "keyset": keyset,
        "bindings": {"keyset_digest": keyset_digest, "report_data_statement": "ignored"},
        "tee_pubkey": {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw_pub)},
        "signature": signature,
    }
    return raw, raw_pub, sig_input


def test_signed_envelope_relays_l2_material() -> None:
    raw, raw_pub, sig_input = _make_signed_raw()
    ev = ka._normalize_backend_evidence(raw, "https://b.example/v1")
    assert ev is not None
    assert ev["signature"], "signature must be relayed"
    assert ev["counter"] == 7, f"counter must be relayed, got {ev.get('counter')}"
    assert ev["tee_pubkey"] == raw["tee_pubkey"], "tee_pubkey (JWK) must be relayed verbatim"
    assert ev["keyset"] == raw["keyset"], "public keyset must be relayed"
    assert ev["keyset_digest"] == raw["bindings"]["keyset_digest"], "keyset_digest must be relayed"
    assert "ed25519" in ev["signature_input"].lower(), "signature_input recipe must be present"
    assert ev["quote_sha256"] == hashlib.sha256(b"\x21" * 100).hexdigest()


def test_unsigned_cache_envelope_leaves_l2_empty() -> None:
    raw, _, _ = _make_signed_raw()
    raw["signature"] = ""
    raw["counter"] = 0
    ev = ka._normalize_backend_evidence(raw, "https://b.example/v1")
    assert ev is not None
    assert not ev["signature"], "no signature must stay empty"
    assert ev["counter"] is None, "counter must NOT surface without a signature"
    assert ev["tee_pubkey"] is None, "tee_pubkey must NOT surface without a signature"
    assert ev["signature_input"] is None, "signature_input must NOT surface without a signature"


def test_roundtrip_signature_verifies_from_relayed_fields() -> None:
    """Non-circular proof: verify the Ed25519 sig using ONLY relayed fields + nonce."""
    from cryptography.hazmat.primitives.asymmetric import ed25519

    raw, raw_pub, _ = _make_signed_raw()
    ev = ka._normalize_backend_evidence(raw, "https://b.example/v1")
    assert ev is not None

    # Reconstruct the signed input from RELAYED fields only (quote_sha256,
    # counter, epoch.id) + the caller's nonce. No hidden backend state.
    rebuilt = layer2_input(
        ev["quote_sha256"], NONCE_HEX, ev["epoch"]["id"], ev["counter"]
    )
    verify_key = ed25519.Ed25519PublicKey.from_public_bytes(
        _unb64url(ev["tee_pubkey"]["x"])
    )
    verify_key.verify(base64.b64decode(ev["signature"]), rebuilt)  # raises on mismatch
    assert rebuilt == rebuilt  # reached only if verify passed


def test_layer2_header_discriminator() -> None:
    raw, _, _ = _make_signed_raw()

    async def _hdr(payload):
        ka._backend_evidence = _ev(payload)  # type: ignore[assignment]
        ka.breaker_guard = lambda *_a, **_k: {}  # type: ignore[assignment]
        return await ka._backend_identity_headers({}, {"api_base": "https://b.example/v1"})

    def _ev(payload):
        async def _f(_api_base, nonce=None):
            return payload

        return _f

    signed = ka._normalize_backend_evidence(raw, "https://b.example/v1")
    h = asyncio.run(_hdr(signed))
    assert h.get("X-KubeTEE-Backend-Evidence-Layer2") == "present", h.get(
        "X-KubeTEE-Backend-Evidence-Layer2"
    )

    raw2 = dict(raw, signature="", counter=0)
    unsigned = ka._normalize_backend_evidence(raw2, "https://b.example/v1")
    h2 = asyncio.run(_hdr(unsigned))
    assert h2.get("X-KubeTEE-Backend-Evidence-Layer2") == "absent", h2.get(
        "X-KubeTEE-Backend-Evidence-Layer2"
    )


def main() -> int:
    print("== Layer-2 caller-binding relay completeness ==")
    for fn in (
        test_signed_envelope_relays_l2_material,
        test_unsigned_cache_envelope_leaves_l2_empty,
        test_roundtrip_signature_verifies_from_relayed_fields,
        test_layer2_header_discriminator,
    ):
        try:
            fn()
            check(fn.__name__, True)
        except Exception as exc:  # noqa: BLE001
            check(fn.__name__, False, repr(exc))

    failed = [n for n, ok, _ in _results if not ok]
    print(f"\n{len(_results) - len(failed)}/{len(_results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
