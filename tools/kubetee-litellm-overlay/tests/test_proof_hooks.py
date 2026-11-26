#!/usr/bin/env python3
"""Offline integration test for the two LiteLLM hooks' WIRING.

Stubs `litellm` + `fastapi`, monkeypatches the network/signing seams
(`_backend_identity_headers`, `_load_serving_key`, `_served_keyset_digest`),
and drives `KubeTEEAttestationLogger.async_pre_call_hook` +
`async_post_call_response_headers_hook` end to end:

  * no opt-in header        -> both hooks no-op (None).
  * X-KubeTEE-Nonce alone   -> fresh path emits attestation headers; NO proof.
  * X-KubeTEE-Proof: 1      -> proof headers + response-bound mode (non-stream),
                               and the proof commits the SAME backend digest the
                               relay emitted.
  * X-KubeTEE-Proof: <hex>  -> anchor kind "nonce" with the nonce value.
  * streaming               -> proof mode falls back to "request-bound".
  * pre-call over limit     -> raises HTTPException 429 with the self-doc body
                               + headers; under the limit returns None.

Exit 0 = all pass. Mirrors the other tests/test_*.py.
"""
from __future__ import annotations

import asyncio
import os
import sys
import types


def _stub_packages() -> None:
    if "litellm" not in sys.modules:
        litellm_mod = types.ModuleType("litellm")
        integrations = types.ModuleType("litellm.integrations")
        custom_logger = types.ModuleType("litellm.integrations.custom_logger")

        class CustomLogger:  # noqa: D401
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
    if "fastapi" not in sys.modules:
        fastapi_mod = types.ModuleType("fastapi")

        class HTTPException(Exception):
            def __init__(self, status_code: int, detail=None, headers=None):
                super().__init__(status_code, detail)
                self.status_code = status_code
                self.detail = detail
                self.headers = headers or {}

        fastapi_mod.HTTPException = HTTPException
        sys.modules["fastapi"] = fastapi_mod


_stub_packages()
HERE = os.path.dirname(os.path.abspath(__file__))
OVERLAY = os.path.dirname(HERE)
sys.path.insert(0, OVERLAY)

import kubetee_attestation as ka  # noqa: E402
import kubetee_proof as kp  # noqa: E402

_results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    _results.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{(' - ' + detail) if detail else ''}")


NONCE = "ab" * 32
BACKEND_DIGEST = "sha256:" + "77" * 32
KEYSET_DIGEST = "sha256:" + "cd" * 32


class _Msg:
    def __init__(self, content):
        self.content = content


class _Choice:
    def __init__(self, content):
        self.message = _Msg(content)


class _Resp:
    def __init__(self, content, model="xiaomi/mimo-v2.6-pro"):
        self.model = model
        self.choices = [_Choice(content)]


def _key():
    from cryptography.hazmat.primitives.asymmetric import ed25519

    return ed25519.Ed25519PrivateKey.generate()


def _install_seams():
    """Patch the network + signing seams so the hooks run offline."""

    async def fake_backend(data, litellm_call_info, nonce=None):
        return {
            "X-KubeTEE-Backend-Evidence-Digest": BACKEND_DIGEST,
            "X-KubeTEE-Backend-Endpoint": "https://pod.example/v1",
            "X-KubeTEE-Backend-Evidence-Source": "cache",
        }

    key = _key()
    ka._backend_identity_headers = fake_backend  # type: ignore[assignment]
    ka._load_serving_key = lambda: key  # type: ignore[assignment]
    ka._served_keyset_digest = lambda: KEYSET_DIGEST  # type: ignore[assignment]
    ka.get_attestation_payload = _fake_payload  # type: ignore[assignment]
    return key


async def _fake_payload(nonce):
    return {"tee": "tdx", "runtime_class": "rt", "report_data_input": "kubetee.attestation.v1",
            "quote": "AAA", "keyset": {}, "bindings": {"report_data_statement": "{}", "keyset_digest": KEYSET_DIGEST}}


def _logger():
    # __init__ calls _mount_once(); neuter it (no FastAPI app in tests).
    ka._mount_once = lambda: None  # type: ignore[assignment]
    return ka.KubeTEEAttestationLogger()


def test_no_header_noop() -> None:
    _install_seams()
    lg = _logger()
    assert asyncio.run(lg.async_post_call_response_headers_hook({}, None, {}, None, {})) is None
    assert asyncio.run(lg.async_pre_call_hook(None, None, {}, "acompletion")) is None


def test_nonce_emits_attestation_not_proof() -> None:
    _install_seams()
    lg = _logger()
    h = asyncio.run(
        lg.async_post_call_response_headers_hook(
            {"messages": []}, None, _Resp("hi"), {"x-kubetee-nonce": NONCE}, {}
        )
    )
    assert "X-KubeTEE-Nonce" in h, h.keys()
    assert "X-KubeTEE-Proof-Signature" not in h, "nonce alone must NOT emit a proof"


def test_proof_1_response_bound_commits_backend_digest() -> None:
    key = _install_seams()
    lg = _logger()
    h = asyncio.run(
        lg.async_post_call_response_headers_hook(
            {"messages": [{"role": "user", "content": "q"}], "model": "m"},
            None, _Resp("the sky is blue"), {"x-kubetee-proof": "1"}, {},
        )
    )
    assert h.get("X-KubeTEE-Proof-Mode") == "response-bound", h.get("X-KubeTEE-Proof-Mode")
    assert h.get("X-KubeTEE-Proof-Anchor-Kind") == "request-digest", h.get("X-KubeTEE-Proof-Anchor-Kind")
    stmt = h["X-KubeTEE-Proof-Statement"]
    assert BACKEND_DIGEST in stmt, "proof must commit the relayed backend digest"
    # The relay's digest and the proof's committed digest must be the SAME value.
    assert h["X-KubeTEE-Backend-Evidence-Digest"] == BACKEND_DIGEST
    # Signature verifies against the statement.
    assert kp.verify_statement(stmt, h["X-KubeTEE-Proof-Signature-Alg"],
                               h["X-KubeTEE-Proof-Signature"], key.public_key())
    # Response digest matches a recomputation over the actual content + the
    # response's own model (extract_response_content reads response.model).
    assert h["X-KubeTEE-Proof-Response-Digest"] == kp.response_digest(
        "the sky is blue", "xiaomi/mimo-v2.6-pro"
    )


def test_proof_nonce_anchor() -> None:
    _install_seams()
    lg = _logger()
    h = asyncio.run(
        lg.async_post_call_response_headers_hook(
            {"messages": []}, None, _Resp("x"), {"x-kubetee-proof": NONCE}, {}
        )
    )
    assert h.get("X-KubeTEE-Proof-Anchor-Kind") == "nonce", h.get("X-KubeTEE-Proof-Anchor-Kind")
    assert h.get("X-KubeTEE-Proof-Anchor-Value") == NONCE


def test_streaming_falls_back_to_request_bound() -> None:
    _install_seams()
    lg = _logger()
    h = asyncio.run(
        lg.async_post_call_response_headers_hook(
            {"messages": [], "stream": True}, None, _Resp("chunks"), {"x-kubetee-proof": "1"}, {}
        )
    )
    assert h.get("X-KubeTEE-Proof-Mode") == "request-bound", h.get("X-KubeTEE-Proof-Mode")


def test_pre_call_429_over_limit() -> None:
    _install_seams()
    lg = _logger()
    ka._fresh_mint_limiter.reset()

    class _Key:
        token = "sk-test-abc"

    data = {"proxy_server_request": {"headers": {"x-kubetee-nonce": NONCE}}}
    # First nonce request allows...
    assert asyncio.run(lg.async_pre_call_hook(_Key(), None, dict(data), "acompletion")) is None
    # ...second within the window raises 429.
    import fastapi

    try:
        asyncio.run(lg.async_pre_call_hook(_Key(), None, dict(data), "acompletion"))
        raised = False
    except fastapi.HTTPException as e:
        raised = True
        assert e.status_code == 429, e.status_code
        assert e.detail["error"]["use_instead"]["header"] == "X-KubeTEE-Proof"
        assert e.headers.get("Retry-After") is not None
    assert raised, "over-limit must raise 429"


def test_pre_call_proof_and_noop_not_limited() -> None:
    _install_seams()
    lg = _logger()
    ka._fresh_mint_limiter.reset()
    class _Key:
        token = "sk-test-xyz"
    # X-KubeTEE-Proof (and no-nonce) requests never consume the mint limiter.
    for _ in range(5):
        d = {"proxy_server_request": {"headers": {"x-kubetee-proof": "1"}}}
        assert asyncio.run(lg.async_pre_call_hook(_Key(), None, d, "acompletion")) is None
    d = {"proxy_server_request": {"headers": {}}}
    assert asyncio.run(lg.async_pre_call_hook(_Key(), None, d, "acompletion")) is None


def main() -> int:
    print("== LiteLLM hook wiring (proof + 429 gate) ==")
    for fn in (
        test_no_header_noop,
        test_nonce_emits_attestation_not_proof,
        test_proof_1_response_bound_commits_backend_digest,
        test_proof_nonce_anchor,
        test_streaming_falls_back_to_request_bound,
        test_pre_call_429_over_limit,
        test_pre_call_proof_and_noop_not_limited,
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
