"""KubeTEE proof-of-inference (kubetee.proof.v1) + fresh-mint rate limiting.

This module is PURE: it imports only `kubetee_binding` (sibling, pure) and the
`cryptography` signing primitives. It never imports `kubetee_attestation`, so
it is trivially testable offline and cannot create an import cycle. The
LiteLLM hook (`kubetee_attestation`) calls into it with resolved inputs.

The contract (docs: kubetee-subnet/docs/CLIENT-FACING-ATTESTATION.md)
------------------------------------------------------------------------
Two independent client opt-in headers, both carrying a binding anchor as their
VALUE. They select two evidence tiers against the SAME routed serving pod:

  X-KubeTEE-Nonce: <64hex>   FRESH silicon mint bound to <64hex>. Expensive
                             (one hardware quote per call). RATE-LIMITED to
                             1 fresh mint / minute / API key -> HTTP 429 beyond.
  X-KubeTEE-Proof:  <val>    PROOF-OF-INFERENCE on the routed pod, NOT
                             rate-limited. <val> is either a <64hex> binding
                             nonce (strongest: binds the client's nonce) or the
                             literal `1` (binds a request-digest anchor instead).
                             Returns the pod's LAST CACHED evidence plus a
                             signature binding it to THIS response.

"the last proof of the pod the prompt is sent to": the evidence attached is the
routed pod's own cache entry (per-backend-endpoint cache in the caller, resolved
from the deployment `api_base`), not a gateway-global blob. Each LiteLLM row
routes to its own pod and thus surfaces its own evidence.

What the proof proves
---------------------
A per-response signature over a canonical statement commits to:
  * `response_digest`  – sha256 of the response content (response-bound) OR the
                         request (request-bound on streaming, where the body is
                         not yet assembled at header-freeze).
  * `request_anchor`   – the client nonce (X-KubeTEE-Proof: <64hex>) or a
                         request digest (X-KubeTEE-Proof: 1). Binds the client's
                         request/freshness anchor.
  * `backend_evidence_digest` – sha256 digest of the attached pod evidence bytes.
  * `keyset_digest`    – the gateway keyset commitment (the signing key is a
                         member of this keyset, so the quote pins the key).
  * `backend_endpoint` + `issued_at` – context + freshness.

Signed by the GATEWAY serving key (the key committed into the gateway's SNP
quote via `keyset_digest`; the same key `_tls_possession_proof` uses). The
BACKEND TEE is vouched by its attached evidence and its own Ed25519 Layer-2
binding over the quote (which rides along in the evidence). So the chain is:
  gateway-sig(response+nonce+evidence)  ->  evidence(quote)  ->  backend-L2(quote+nonce).
This is the strongest proof achievable gateway-only: the gateway attests "I
assembled this response from backend X (evidence attached), bound to your
request/response." It is NOT a quote whose REPORTDATA is the response hash —
that would require the silicon to sign the response (impossible: the gateway
assembles the response and silicon cannot sign arbitrary post-hoc data).
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Any, Final

import kubetee_binding

PROOF_PURPOSE: Final = "kubetee.proof.v1"
PROOF_VERSION: Final = "kubetee.proof.v1"

# Self-describing response-digest recipes (emitted verbatim so a verifier never
# has to guess the byte layout). RESPONSE_BOUND is computable only on the
# non-streaming path (the assembled body exists at header-freeze); on streaming
# we fall back to REQUEST_BOUND (binds the request, not the output) and SAY SO.
RECIPE_RESPONSE: Final = "sha256(utf8(jcs({content,model})))"
RECIPE_REQUEST: Final = "sha256(utf8(jcs({messages,model})))"
MODE_RESPONSE_BOUND: Final = "response-bound"
MODE_REQUEST_BOUND: Final = "request-bound"


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _sha256_hex(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def sign_statement(statement: str, key: Any) -> tuple[str, str]:
    """Sign the UTF-8 statement with the gateway key -> (alg, sig_b64).

    Algorithm is REPORTED, not assumed: Ed25519 (EdDSA), EC P-256 (ES256 raw
    r||s, JOSE wire format), or RSA (RS256 PKCS1v15 over SHA-256). Matches the
    dual-alg reporting the spec's verifier contract already accepts.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, utils

    msg = statement.encode("utf-8")
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return "EdDSA", _b64(key.sign(msg))
    if isinstance(key, ec.EllipticCurvePrivateKey):
        der = key.sign(msg, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        size = key.curve.key_size // 8
        return "ES256", _b64(r.to_bytes(size, "big") + s.to_bytes(size, "big"))
    # RSA (cert-manager litellm-tls legacy key).
    return "RS256", _b64(key.sign(msg, padding.PKCS1v15(), hashes.SHA256()))


def verify_statement(statement: str, alg: str, sig_b64: str, public_key: Any) -> bool:
    """Reference verifier (tests only): True if the signature is valid."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, utils

    msg = statement.encode("utf-8")
    sig = base64.b64decode(sig_b64)
    try:
        if alg == "EdDSA":
            public_key.verify(sig, msg)
            return True
        if alg == "ES256":
            size = public_key.curve.key_size // 8
            der = utils.encode_dss_signature(
                int.from_bytes(sig[:size], "big"), int.from_bytes(sig[size:], "big")
            )
            public_key.verify(der, msg, ec.ECDSA(hashes.SHA256()))
            return True
        if alg == "RS256":
            public_key.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
            return True
        return False
    except Exception:
        return False


def extract_response_content(response: Any) -> tuple[str, str]:
    """(content, model) from a non-streaming ModelResponse, defensively.

    Concatenates every choice's message content (usually one). Model is read
    from the response when present. Returns ("", model_or_empty) when the
    response carries no parseable content (the caller then degrades to
    request-bound rather than sign an empty digest silently).
    """
    content_parts: list[str] = []
    model = ""
    try:
        model = str(getattr(response, "model", "") or "")
    except Exception:
        model = ""
    try:
        choices = getattr(response, "choices", None) or []
        for ch in choices:
            msg = getattr(ch, "message", None)
            piece = getattr(msg, "content", None) if msg is not None else None
            if isinstance(piece, str):
                content_parts.append(piece)
            elif piece is not None:
                content_parts.append(str(piece))
    except Exception:
        pass
    return "".join(content_parts), model


def response_digest(content: str, model: str) -> str:
    """sha256 over jcs({content, model}); the response-bound digest."""
    blob = kubetee_binding.jcs({"content": content, "model": model})
    return _sha256_hex(blob.encode("utf-8"))


def request_digest(messages: Any, model: Any) -> str:
    """sha256 over jcs({messages, model}); the request-bound anchor/digest.

    `messages` is normalized to a JSON-stable form first (sorted keys, compact)
    so the digest is reproducible from the request the client sent. This is the
    FALLBACK anchor for `X-KubeTEE-Proof: 1`; a client wanting the strongest
    per-request freshness anchor sends `X-KubeTEE-Proof: <64hex>` (a nonce).
    """
    stable = json.dumps(
        {"messages": messages, "model": model},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return _sha256_hex(stable.encode("utf-8"))


def build_statement(
    *,
    response_mode: str,
    response_input: str,
    response_digest_value: str,
    request_anchor: dict[str, str],
    backend_evidence_digest: str,
    backend_endpoint: str,
    keyset_digest: str,
    issued_at: str,
) -> str:
    """The canonical (RFC 8785) proof statement, ready to sign."""
    return kubetee_binding.jcs(
        {
            "purpose": PROOF_PURPOSE,
            "version": PROOF_VERSION,
            "response_mode": response_mode,
            "response_input": response_input,
            "response_digest": response_digest_value,
            "request_anchor": request_anchor,
            "backend_evidence_digest": backend_evidence_digest,
            "backend_endpoint": backend_endpoint,
            "keyset_digest": keyset_digest,
            "issued_at": issued_at,
        }
    )


def proof_headers(
    *,
    response_mode: str,
    response_input: str,
    response_digest_value: str,
    request_anchor: dict[str, str],
    backend_evidence_digest: str,
    backend_endpoint: str,
    keyset_digest: str,
    issued_at: str,
    signing_key: Any,
) -> dict[str, str]:
    """Build the `X-KubeTEE-Proof-*` header set (statement + signature).

    Fail-closed: if `signing_key` is None, returns ONLY the unsigned metadata
    with `X-KubeTEE-Proof-Error: signing key unavailable` and NO signature — a
    proof is never fabricated without its key.
    """
    out: dict[str, str] = {
        "X-KubeTEE-Proof-Spec": PROOF_VERSION,
        "X-KubeTEE-Proof-Mode": response_mode,
        "X-KubeTEE-Proof-Response-Input": response_input,
        "X-KubeTEE-Proof-Response-Digest": response_digest_value,
        "X-KubeTEE-Proof-Anchor-Kind": request_anchor.get("kind", ""),
        "X-KubeTEE-Proof-Anchor-Value": request_anchor.get("value", ""),
        "X-KubeTEE-Proof-Backend-Evidence-Digest": backend_evidence_digest,
        "X-KubeTEE-Proof-Keyset-Digest": keyset_digest,
        "X-KubeTEE-Proof-Issued-At": issued_at,
    }
    statement = build_statement(
        response_mode=response_mode,
        response_input=response_input,
        response_digest_value=response_digest_value,
        request_anchor=request_anchor,
        backend_evidence_digest=backend_evidence_digest,
        backend_endpoint=backend_endpoint,
        keyset_digest=keyset_digest,
        issued_at=issued_at,
    )
    out["X-KubeTEE-Proof-Statement"] = statement
    if signing_key is None:
        out["X-KubeTEE-Proof-Error"] = "signing key unavailable"
        return out
    alg, sig = sign_statement(statement, signing_key)
    out["X-KubeTEE-Proof-Signature"] = sig
    out["X-KubeTEE-Proof-Signature-Alg"] = alg
    return out


# ---------------------------------------------------------------------------
# Fresh-mint rate limiting (X-KubeTEE-Nonce only) — 1 fresh mint / minute / key
# ---------------------------------------------------------------------------
class FreshMintLimiter:
    """Sliding-window limiter: at most `per_window` fresh mints per key.

    Deliberately minimal and in-memory (like the breaker + evidence cache this
    sits beside). `check` CONSUMES a permit on allow, so it must be called once
    per nonce-bearing request at the pre-call gate.
    """

    __slots__ = ("per_window", "window_s", "_last")

    def __init__(self, per_window: int = 1, window_s: float = 60.0) -> None:
        self.per_window = max(1, int(per_window))
        self.window_s = float(window_s)
        self._last: dict[str, list[float]] = {}

    def check(self, key: str) -> tuple[bool, float]:
        """(allowed, retry_after_seconds). Consumes a permit when allowed."""
        now = time.monotonic()
        interval = self.window_s / self.per_window
        stamps = self._last.setdefault(key, [])
        # Drop stamps outside the window.
        cutoff = now - interval
        stamps[:] = [t for t in stamps if t > cutoff]
        if len(stamps) >= self.per_window:
            retry = interval - (now - stamps[0])
            return False, max(0.0, retry)
        stamps.append(now)
        return True, 0.0

    def reset(self) -> None:
        self._last.clear()


def rate_limit_headers(limit: int, window_s: float, retry_after: float | None = None) -> dict[str, str]:
    out = {
        "X-KubeTEE-RateLimit-Limit": str(limit),
        "X-KubeTEE-RateLimit-Window": f"{int(window_s)}s",
        "X-KubeTEE-RateLimit-Policy": (
            "x-kubetee-nonce (fresh mint) is limited to "
            f"{limit} per {int(window_s)}s per key"
        ),
        "X-KubeTEE-RateLimit-Alternative": (
            "send X-KubeTEE-Proof: 1 to get the last evidence now "
            "(uncached proof, no rate limit)"
        ),
    }
    if retry_after is not None:
        out["Retry-After"] = str(int(round(retry_after)))
    return out


def rate_limit_error(limit: int, window_s: float, retry_after: float) -> dict[str, Any]:
    """The self-documenting 429 body. Names the limit AND the workaround in-band
    so an agent hitting it needs zero external docs to know what to do next."""
    return {
        "error": {
            "type": "kubetee_evidence_rate_limited",
            "message": (
                "X-KubeTEE-Nonce (fresh silicon mint) is limited to "
                f"{limit} per {int(window_s)}s per key. For the last attestation "
                "+ a proof binding this response to the TEE now, send header "
                "`X-KubeTEE-Proof: 1` (no rate limit). Retry the fresh mint after "
                f"{int(round(retry_after))}s."
            ),
            "limit": f"{limit}/{int(window_s)}s per key",
            "retry_after_seconds": int(round(retry_after)),
            "use_instead": {
                "header": "X-KubeTEE-Proof",
                "value": "1",
                "effect": (
                    "returns the most recent hardware attestation of the serving "
                    "pod + a signature binding this response and your request to "
                    "the attested TEE (uncached proof, no rate limit)"
                ),
            },
        }
    }
