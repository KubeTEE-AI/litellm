#!/usr/bin/env python3
"""Offline regression for the proof-of-inference + fresh-mint rate limiter.

Run from anywhere; needs no cluster, no Trustee, no network. Stubs the
`litellm` package and exercises `kubetee_proof` (pure) end to end:

  * proof statement + signature ROUND-TRIPS for Ed25519 (and reports alg).
  * response-bound vs request-bound digests are distinct + reproducible.
  * request_anchor kinds: nonce / literal-1 (request-digest) are correct.
  * fail-closed: no signing key -> error surfaced, NO signature fabricated.
  * rate limiter: 1/min per key allows one, rejects the second with a
    retry_after, isolates keys, and resets after the window.
  * the 429 body is self-documenting (limit + `use_instead` workaround).
  * extract_response_content parses a stub non-streaming ModelResponse.

Exit 0 = all pass. Mirrors test_breaker.py / test_relay_l2.py.
"""
from __future__ import annotations

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

import kubetee_proof as kp  # noqa: E402

_results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    _results.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{(' - ' + detail) if detail else ''}")


NONCE = "ab" * 32
KEYSET_DIGEST = "sha256:" + "cd" * 32
EVIDENCE_DIGEST = "sha256:" + "ef" * 32
ENDPOINT = "https://mimo-v2-6-pro.na-us-dallas-132.inference.kubetee.ai/v1"
ISSUED_AT = "2026-11-27T00:30:00Z"


def _ed25519():
    from cryptography.hazmat.primitives.asymmetric import ed25519

    return ed25519.Ed25519PrivateKey.generate()


def _make_headers(key, anchor_value=NONCE):
    anchor_kind = "nonce" if anchor_value != "1" else "request-digest"
    req_anchor = (
        {"kind": anchor_kind, "value": anchor_value}
        if anchor_kind == "nonce"
        else {"kind": "request-digest", "value": "sha256:" + "11" * 32}
    )
    resp_digest = kp.response_digest("hello world", "xiaomi/mimo-v2.6-pro")
    return kp.proof_headers(
        response_mode=kp.MODE_RESPONSE_BOUND,
        response_input=kp.RECIPE_RESPONSE,
        response_digest_value=resp_digest,
        request_anchor=req_anchor,
        backend_evidence_digest=EVIDENCE_DIGEST,
        backend_endpoint=ENDPOINT,
        keyset_digest=KEYSET_DIGEST,
        issued_at=ISSUED_AT,
        signing_key=key,
    ), resp_digest, req_anchor


def test_roundtrip_ed25519_signature_verifies() -> None:
    key = _ed25519()
    pub = key.public_key()
    hdrs, resp_digest, req_anchor = _make_headers(key)
    statement = hdrs["X-KubeTEE-Proof-Statement"]
    alg = hdrs["X-KubeTEE-Proof-Signature-Alg"]
    sig = hdrs["X-KubeTEE-Proof-Signature"]
    assert alg == "EdDSA", alg
    assert kp.verify_statement(statement, alg, sig, pub), "Ed25519 verify must pass"
    # The statement must commit to the response + anchor + evidence + keyset.
    for frag in (resp_digest, req_anchor["value"], EVIDENCE_DIGEST, KEYSET_DIGEST):
        assert frag in statement, f"{frag} must be committed in the statement"
    # Tamper: flip one byte in the response digest -> verify must FAIL.
    tampered = statement.replace(resp_digest, resp_digest[:-1] + ("0" if resp_digest[-1] != "0" else "1"))
    assert not kp.verify_statement(tampered, alg, sig, pub), "tampered statement must fail"


def test_ec_p256_signature_reports_es256() -> None:
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    pub = key.public_key()
    hdrs, _, _ = _make_headers(key)
    assert hdrs["X-KubeTEE-Proof-Signature-Alg"] == "ES256", hdrs["X-KubeTEE-Proof-Signature-Alg"]
    assert kp.verify_statement(
        hdrs["X-KubeTEE-Proof-Statement"], "ES256", hdrs["X-KubeTEE-Proof-Signature"], pub
    ), "ES256 verify must pass"


def test_response_vs_request_bound_digests_differ() -> None:
    d_resp = kp.response_digest("hello", "m1")
    d_req = kp.request_digest([{"role": "user", "content": "hello"}], "m1")
    assert d_resp != d_req, "response-bound and request-bound digests must differ"
    # Reproducible.
    assert d_resp == kp.response_digest("hello", "m1")
    assert d_req == kp.request_digest([{"role": "user", "content": "hello"}], "m1")
    # Content-sensitive.
    assert d_resp != kp.response_digest("hello!", "m1")


def test_fail_closed_no_signing_key() -> None:
    hdrs, _, _ = _make_headers(None)
    assert "X-KubeTEE-Proof-Error" in hdrs, "missing-key must surface an error"
    assert "X-KubeTEE-Proof-Signature" not in hdrs, "must NOT fabricate a signature"
    assert "X-KubeTEE-Proof-Statement" in hdrs, "statement still present for transparency"


def test_rate_limiter_one_per_minute_per_key() -> None:
    lim = kp.FreshMintLimiter(per_window=1, window_s=60.0)
    ok1, r1 = lim.check("keyA")
    ok2, r2 = lim.check("keyA")
    assert ok1 and r1 == 0.0, f"first call must allow, got {(ok1, r1)}"
    assert not ok2, "second call in window must reject"
    assert r2 > 0.0, f"retry_after must be positive, got {r2}"
    assert r2 <= 60.0, f"retry_after must be <= window, got {r2}"


def test_rate_limiter_isolates_keys() -> None:
    lim = kp.FreshMintLimiter(per_window=1, window_s=60.0)
    assert lim.check("keyA")[0]
    assert lim.check("keyB")[0], "different key must not be blocked by keyA"
    assert not lim.check("keyB")[0], "keyB second call must reject"


def test_rate_limiter_per_window_two() -> None:
    lim = kp.FreshMintLimiter(per_window=2, window_s=60.0)
    assert lim.check("k")[0]
    assert lim.check("k")[0], "second within per_window=2 must allow"
    assert not lim.check("k")[0], "third must reject"


def test_rate_limit_error_is_self_documenting() -> None:
    err = kp.rate_limit_error(1, 60, 42.0)
    e = err["error"]
    assert "X-KubeTEE-Nonce" in e["message"] and "X-KubeTEE-Proof: 1" in e["message"], e["message"]
    assert e["use_instead"]["header"] == "X-KubeTEE-Proof"
    assert e["use_instead"]["value"] == "1"
    assert e["retry_after_seconds"] == 42
    assert "no rate limit" in e["use_instead"]["effect"].lower()


def test_rate_limit_headers() -> None:
    h = kp.rate_limit_headers(1, 60, 42.0)
    assert h["Retry-After"] == "42"
    assert h["X-KubeTEE-RateLimit-Limit"] == "1"
    assert "X-KubeTEE-Proof" in h["X-KubeTEE-RateLimit-Alternative"]


def test_extract_response_content_stub() -> None:
    class _Msg:
        content = "the answer is 42"

    class _Choice:
        message = _Msg()

    class _Resp:
        model = "xiaomi/mimo-v2.6-pro"
        choices = [_Choice()]

    content, model = kp.extract_response_content(_Resp())
    assert content == "the answer is 42", content
    assert model == "xiaomi/mimo-v2.6-pro", model


def test_request_anchor_nonce_vs_literal() -> None:
    # X-KubeTEE-Proof: <64hex> -> kind nonce; X-KubeTEE-Proof: 1 -> request-digest.
    hdrs_n, _, anchor_n = _make_headers(_ed25519(), anchor_value=NONCE)
    assert hdrs_n["X-KubeTEE-Proof-Anchor-Kind"] == "nonce"
    assert hdrs_n["X-KubeTEE-Proof-Anchor-Value"] == NONCE
    hdrs_1, _, anchor_1 = _make_headers(_ed25519(), anchor_value="1")
    assert hdrs_1["X-KubeTEE-Proof-Anchor-Kind"] == "request-digest"
    assert anchor_1["kind"] == "request-digest"


def main() -> int:
    print("== proof-of-inference + fresh-mint rate limiter ==")
    for fn in (
        test_roundtrip_ed25519_signature_verifies,
        test_ec_p256_signature_reports_es256,
        test_response_vs_request_bound_digests_differ,
        test_fail_closed_no_signing_key,
        test_rate_limiter_one_per_minute_per_key,
        test_rate_limiter_isolates_keys,
        test_rate_limiter_per_window_two,
        test_rate_limit_error_is_self_documenting,
        test_rate_limit_headers,
        test_extract_response_content_stub,
        test_request_anchor_nonce_vs_literal,
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
