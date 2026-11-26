"""CI-enforced gates for proof-of-inference + the fresh-mint 429 gate.

Two independent client opt-in headers, both on the SAME routed serving pod:

  * ``X-KubeTEE-Proof: <64hex> | 1`` — proof-of-inference on the routed pod's
    LAST CACHED evidence plus a gateway-key signature binding it to THIS
    response and the caller's anchor. NOT rate-limited.
  * ``X-KubeTEE-Nonce: <64hex>`` — a FRESH silicon mint, RATE-LIMITED to
    1 / minute / key -> a self-documenting HTTP 429 naming the
    ``X-KubeTEE-Proof: 1`` workaround in-band.

These tests are network-free and secret-free (the signing key is a throwaway
Ed25519 key, the network/signing seams are monkeypatched) and gate both the
pure proof construction and the LiteLLM hook wiring so a measured release
cannot regress either:

  * Ed25519 signature round-trips and tampering a committed field fails.
  * response-bound vs request-bound digests differ and are reproducible.
  * fail-closed: no signing key -> error surfaced, NO signature fabricated.
  * ``X-KubeTEE-Proof: 1`` -> response-bound + request-digest anchor, and the
    proof commits the SAME backend evidence digest the relay emitted.
  * ``X-KubeTEE-Proof: <64hex>`` -> anchor kind ``nonce``.
  * streaming -> falls back to ``request-bound``.
  * pre-call over the limit -> raises HTTPException 429 with the self-doc body
    + ``Retry-After``; under the limit / proof-only / no-header do not 429.

The rich standalone runners live beside the overlay in
``tools/kubetee-litellm-overlay/tests/{test_proof,test_proof_hooks}.py``; this
file pins the same gates in the pytest suite CI actually collects.
"""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import types
from pathlib import Path
from typing import Any, Final

import pytest

_OVERLAY_DIR: Final = (
    Path(__file__).resolve().parents[4] / "tools" / "kubetee-litellm-overlay"
)


def _ensure_packages() -> None:
    """Register minimal ``litellm`` + ``fastapi`` stubs only when absent.

    Under CI the packaged ``litellm``/``fastapi`` are importable and win; the
    standalone runner needs the stub. Mirrors ``test_kubetee_snp_cert_chain``.
    """
    try:  # pragma: no cover - trivial import probe
        import litellm.integrations.custom_logger  # noqa: F401
    except Exception:
        litellm_mod = types.ModuleType("litellm")
        integrations = types.ModuleType("litellm.integrations")
        custom_logger = types.ModuleType("litellm.integrations.custom_logger")

        class CustomLogger:  # noqa: D401 - stub base class
            pass

        custom_logger.CustomLogger = CustomLogger
        logging_mod = types.ModuleType("litellm._logging")

        class _L:
            def error(self, *a: Any, **k: Any) -> None:
                pass

            def info(self, *a: Any, **k: Any) -> None:
                pass

        logging_mod.verbose_proxy_logger = _L()
        sys.modules["litellm"] = litellm_mod
        sys.modules["litellm.integrations"] = integrations
        sys.modules["litellm.integrations.custom_logger"] = custom_logger
        sys.modules["litellm._logging"] = logging_mod

    try:  # pragma: no cover - trivial import probe
        import fastapi  # noqa: F401
    except Exception:
        fastapi_mod = types.ModuleType("fastapi")

        class HTTPException(Exception):
            def __init__(self, status_code: int, detail=None, headers=None):
                super().__init__(status_code, detail)
                self.status_code = status_code
                self.detail = detail
                self.headers = headers or {}

        fastapi_mod.HTTPException = HTTPException
        sys.modules["fastapi"] = fastapi_mod


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _OVERLAY_DIR / f"{name}.py")
    assert spec is not None and spec.loader is not None, f"cannot load {name}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_ensure_packages()
sys.path.insert(0, str(_OVERLAY_DIR))  # intra-overlay imports (kubetee_binding, ...)
kp: Final = _load("kubetee_proof")
ka: Final = _load("kubetee_attestation")

_NONCE: Final = "ab" * 32
_BACKEND_DIGEST: Final = "sha256:" + "77" * 32
_KEYSET_DIGEST: Final = "sha256:" + "cd" * 32


def _ed25519():
    from cryptography.hazmat.primitives.asymmetric import ed25519

    return ed25519.Ed25519PrivateKey.generate()


class _Msg:
    def __init__(self, content: str):
        self.content = content


class _Choice:
    def __init__(self, content: str):
        self.message = _Msg(content)


class _Resp:
    def __init__(self, content: str, model: str = "xiaomi/mimo-v2.6-pro"):
        self.model = model
        self.choices = [_Choice(content)]


def _install_seams():
    """Patch the network + signing seams so the hooks run offline."""

    async def fake_backend(data, litellm_call_info, nonce=None):
        return {
            "X-KubeTEE-Backend-Evidence-Digest": _BACKEND_DIGEST,
            "X-KubeTEE-Backend-Endpoint": "https://pod.example/v1",
            "X-KubeTEE-Backend-Evidence-Source": "cache",
        }

    async def fake_payload(nonce):
        return {
            "tee": "tdx",
            "runtime_class": "rt",
            "report_data_input": "kubetee.attestation.v1",
            "quote": "AAA",
            "keyset": {},
            "bindings": {
                "report_data_statement": "{}",
                "keyset_digest": _KEYSET_DIGEST,
            },
        }

    key = _ed25519()
    ka._backend_identity_headers = fake_backend  # type: ignore[assignment]
    ka._load_serving_key = lambda: key  # type: ignore[assignment]
    ka._served_keyset_digest = lambda: _KEYSET_DIGEST  # type: ignore[assignment]
    ka.get_attestation_payload = fake_payload  # type: ignore[assignment]
    ka._mount_once = lambda: None  # type: ignore[assignment]
    ka._fresh_mint_limiter.reset()
    return key


def _logger():
    return ka.KubeTEEAttestationLogger()


def test_ed25519_roundtrip_and_tamper_fails() -> None:
    key = _ed25519()
    resp_digest = kp.response_digest("hello world", "xiaomi/mimo-v2.6-pro")
    anchor = {"kind": "nonce", "value": _NONCE}
    hdrs = kp.proof_headers(
        response_mode=kp.MODE_RESPONSE_BOUND,
        response_input=kp.RECIPE_RESPONSE,
        response_digest_value=resp_digest,
        request_anchor=anchor,
        backend_evidence_digest=_BACKEND_DIGEST,
        backend_endpoint="https://pod.example/v1",
        keyset_digest=_KEYSET_DIGEST,
        issued_at="2026-11-27T00:30:00Z",
        signing_key=key,
    )
    assert hdrs["X-KubeTEE-Proof-Signature-Alg"] == "EdDSA"
    stmt = hdrs["X-KubeTEE-Proof-Statement"]
    assert kp.verify_statement(stmt, "EdDSA", hdrs["X-KubeTEE-Proof-Signature"], key.public_key())
    # The statement commits response + anchor + evidence + keyset.
    for frag in (resp_digest, _NONCE, _BACKEND_DIGEST, _KEYSET_DIGEST):
        assert frag in stmt
    # Tamper the committed response digest -> verify must FAIL.
    tampered = stmt.replace(resp_digest, resp_digest[:-1] + ("0" if resp_digest[-1] != "0" else "1"))
    assert not kp.verify_statement(tampered, "EdDSA", hdrs["X-KubeTEE-Proof-Signature"], key.public_key())


def test_response_vs_request_bound_digests_differ() -> None:
    d_resp = kp.response_digest("hello", "m1")
    d_req = kp.request_digest([{"role": "user", "content": "hello"}], "m1")
    assert d_resp != d_req
    assert d_resp == kp.response_digest("hello", "m1")
    assert d_req == kp.request_digest([{"role": "user", "content": "hello"}], "m1")
    assert d_resp != kp.response_digest("hello!", "m1")


def test_fail_closed_no_signing_key() -> None:
    hdrs = kp.proof_headers(
        response_mode=kp.MODE_RESPONSE_BOUND,
        response_input=kp.RECIPE_RESPONSE,
        response_digest_value=kp.response_digest("x", "m"),
        request_anchor={"kind": "nonce", "value": _NONCE},
        backend_evidence_digest=_BACKEND_DIGEST,
        backend_endpoint="https://pod.example/v1",
        keyset_digest=_KEYSET_DIGEST,
        issued_at="2026-11-27T00:30:00Z",
        signing_key=None,
    )
    assert "X-KubeTEE-Proof-Error" in hdrs
    assert "X-KubeTEE-Proof-Signature" not in hdrs
    assert "X-KubeTEE-Proof-Statement" in hdrs


def test_proof_1_response_bound_commits_backend_digest() -> None:
    key = _install_seams()
    lg = _logger()
    h = asyncio.run(
        lg.async_post_call_response_headers_hook(
            {"messages": [{"role": "user", "content": "q"}], "model": "m"},
            None,
            _Resp("the sky is blue"),
            {"x-kubetee-proof": "1"},
            {},
        )
    )
    assert h.get("X-KubeTEE-Proof-Mode") == "response-bound"
    assert h.get("X-KubeTEE-Proof-Anchor-Kind") == "request-digest"
    stmt = h["X-KubeTEE-Proof-Statement"]
    assert _BACKEND_DIGEST in stmt
    assert h["X-KubeTEE-Backend-Evidence-Digest"] == _BACKEND_DIGEST
    assert kp.verify_statement(
        stmt,
        h["X-KubeTEE-Proof-Signature-Alg"],
        h["X-KubeTEE-Proof-Signature"],
        key.public_key(),
    )
    assert h["X-KubeTEE-Proof-Response-Digest"] == kp.response_digest(
        "the sky is blue", "xiaomi/mimo-v2.6-pro"
    )


def test_proof_nonce_anchor() -> None:
    _install_seams()
    lg = _logger()
    h = asyncio.run(
        lg.async_post_call_response_headers_hook(
            {"messages": []}, None, _Resp("x"), {"x-kubetee-proof": _NONCE}, {}
        )
    )
    assert h.get("X-KubeTEE-Proof-Anchor-Kind") == "nonce"
    assert h.get("X-KubeTEE-Proof-Anchor-Value") == _NONCE


def test_streaming_falls_back_to_request_bound() -> None:
    _install_seams()
    lg = _logger()
    h = asyncio.run(
        lg.async_post_call_response_headers_hook(
            {"messages": [], "stream": True}, None, _Resp("chunks"), {"x-kubetee-proof": "1"}, {}
        )
    )
    assert h.get("X-KubeTEE-Proof-Mode") == "request-bound"


def test_nonce_emits_attestation_not_proof() -> None:
    _install_seams()
    lg = _logger()
    h = asyncio.run(
        lg.async_post_call_response_headers_hook(
            {"messages": []}, None, _Resp("hi"), {"x-kubetee-nonce": _NONCE}, {}
        )
    )
    assert "X-KubeTEE-Nonce" in h
    assert "X-KubeTEE-Proof-Signature" not in h


def test_no_header_noop() -> None:
    _install_seams()
    lg = _logger()
    assert asyncio.run(lg.async_post_call_response_headers_hook({}, None, {}, None, {})) is None
    assert asyncio.run(lg.async_pre_call_hook(None, None, {}, "acompletion")) is None


def test_pre_call_429_over_limit() -> None:
    _install_seams()
    lg = _logger()
    import fastapi

    class _Key:
        token = "sk-test-abc"

    data = {"proxy_server_request": {"headers": {"x-kubetee-nonce": _NONCE}}}
    # First nonce request allows ...
    assert asyncio.run(lg.async_pre_call_hook(_Key(), None, dict(data), "acompletion")) is None
    # ... the second within the window raises a self-documenting 429.
    with pytest.raises(fastapi.HTTPException) as exc:
        asyncio.run(lg.async_pre_call_hook(_Key(), None, dict(data), "acompletion"))
    e = exc.value
    assert e.status_code == 429
    assert e.detail["error"]["use_instead"]["header"] == "X-KubeTEE-Proof"
    assert e.detail["error"]["use_instead"]["value"] == "1"
    assert e.headers.get("Retry-After") is not None
    assert "X-KubeTEE-Proof" in e.headers.get("X-KubeTEE-RateLimit-Alternative", "")


def test_pre_call_proof_and_noop_not_limited() -> None:
    _install_seams()
    lg = _logger()

    class _Key:
        token = "sk-test-xyz"

    # X-KubeTEE-Proof (and no-nonce) requests never consume the mint limiter.
    for _ in range(5):
        d = {"proxy_server_request": {"headers": {"x-kubetee-proof": "1"}}}
        assert asyncio.run(lg.async_pre_call_hook(_Key(), None, d, "acompletion")) is None
    d = {"proxy_server_request": {"headers": {}}}
    assert asyncio.run(lg.async_pre_call_hook(_Key(), None, d, "acompletion")) is None
