# KubeTEE client-facing attestation for the LiteLLM gateway (CPU TDX guest).
#
# Mounted into the LiteLLM container via the eastwest-fetch-certs ConfigMap
# (subPath into site-packages), loaded as a custom callback:
#   callbacks: ["dynamic_rate_limiter_v3", "prometheus",
#               "kubetee_attestation.kubetee_attestation_logger"]
#
# What it does
# ------------
# 1. GET /v1/attestation?nonce=<64 hex>
#      Mints a FRESH TDX quote with the client nonce bound into REPORTDATA
#      (via the in-guest api-server-rest /aa/evidence on 127.0.0.1:8006).
#      3-replica caveat: proves "a gateway replica", not "the replica that
#      served a given chat" — use inline evidence (2) for that binding.
# 2. Inline evidence (opt-in): client sends X-KubeTEE-Nonce: <64 hex> on
#      /v1/chat/completions; the response then carries
#      X-KubeTEE-Attestation-Quote (b64 TDX quote) + backend identity
#      headers on the SAME response, binding proof to the serving replica.
#
# TLS-possession proof (both surfaces)
# ------------------------------------
# llm.kubetee.ai is TLS PASSTHROUGH — the client's TLS session terminates
# INSIDE this guest, on the litellm-tls secret's key. Both surfaces
# additionally sign the nonce with that private key (RS256 over
# sha256(nonce)); the client verifies the signature against the leaf
# certificate from its OWN TLS session. This proves the TDX guest that
# minted the quote holds the private key of the exact cert the client is
# connected to — replica pinning without trusting any self-reported field.
#
# Nonce binding — the critical semantics
# --------------------------------------
# The CoCo AA /aa/evidence binds the raw runtime_data bytes (zero-padded to
# 64 B) into REPORTDATA. Intel Trust Authority's verification expects
# REPORTDATA == SHA512(runtime_data supplied in the /attest request).
# We therefore pass SHA512(nonce) (exactly 64 B) as runtime_data to the AA,
# and the client submits the RAW nonce as runtime_data to ITA:
#   ITA computes SHA512(raw nonce) == REPORTDATA  ✓
# (Verified against intel/trustauthority-client-for-python TDXAdapter and
# guest-components attester/tdx at pinned commit eae0bf63.)
#
# Non-JSON runtime_data is echoed by ITA as attester_runtime_data /
# attester_held_data claims in the token.
#
# Auth: LiteLLM attaches user_api_key_auth to routes it knows; a custom
# app.add_api_route endpoint does NOT get the auth dependency by default —
# it is public on the guest network. The endpoint discloses no secrets
# (nonce + TDX quote of THIS guest only).

import base64
import hashlib
import json
import os
import re
import socket
from typing import Any

from litellm.integrations.custom_logger import CustomLogger

_NONCE_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_AA_BASE = os.environ.get("KUBETEE_AA_BASE", "http://127.0.0.1:8006")
_NONCE_HEADER = "x-kubetee-nonce"
_TLS_KEY_PATH = os.environ.get("KUBETEE_TLS_KEY", "/etc/tls/tls.key")
_TLS_CERT_PATH = os.environ.get("KUBETEE_TLS_CERT", "/etc/tls/tls.crt")


def _pod_name() -> str | None:
    try:
        return os.environ.get("POD_NAME") or socket.gethostname()
    except Exception:
        return None


def _validate_nonce(nonce: str | None) -> str | None:
    """Return the normalized nonce or None if malformed."""
    if not nonce:
        return None
    nonce = nonce.strip()
    if not _NONCE_RE.match(nonce):
        return None
    return nonce.lower()


def _tls_possession_proof(nonce: str) -> dict | None:
    """Sign the nonce with the pod's TLS private key (POSSESSION proof).

    The client verifies the signature against the leaf certificate from ITS
    OWN TLS session (llm.kubetee.ai terminates inside this guest). A valid
    signature proves the TDX guest that minted the attestation payload also
    holds the private key of the cert the client is connected to — binding
    the quote to the exact serving pod, not just "some gateway replica".

    Returns {"tls_signature": b64, "tls_signature_alg": "RS256",
             "tls_signature_input": "sha256(nonce)", "tls_cert_sha256": hex}
    or None if the key is unavailable (best-effort; the quote is still the
    primary evidence).
    """
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        with open(_TLS_KEY_PATH, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        # RS256 semantics: signature over SHA256(nonce). Pass the raw nonce;
        # the lib hashes internally (same bytes as Prehashed(digest)).
        sig = key.sign(
            nonce.encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        cert_fp: str | None = None
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.serialization import Encoding

            with open(_TLS_CERT_PATH, "rb") as f:
                cert_pem = f.read()
            # tls.crt carries the full chain (leaf + intermediates); the
            # client fingerprint is of the LEAF (first cert in the file,
            # and the one its TLS session serves). Hash only that.
            first_pem = cert_pem.split(b"-----END CERTIFICATE-----")[0] + b"-----END CERTIFICATE-----"
            der = x509.load_pem_x509_certificate(first_pem).public_bytes(Encoding.DER)
            cert_fp = hashlib.sha256(der).hexdigest()
        except Exception:
            pass
        return {
            "tls_signature": base64.b64encode(sig).decode("ascii"),
            "tls_signature_alg": "RS256",
            "tls_signature_input": "sha256(nonce)",
            "tls_cert_sha256": cert_fp,
        }
    except Exception:
        return None


async def _aa_get_evidence(runtime_data_b64url: str) -> dict:
    """Call in-guest /aa/evidence; parse the TdxEvidence JSON envelope.

    Returns {"quote": <b64 str>, "cc_eventlog": <b64 str|None>} or raises.
    The AA returns JSON bytes (content-type is octet-stream, cosmetic).
    """
    import httpx

    url = (
        f"{_AA_BASE}/aa/evidence"
        f"?runtime_data={runtime_data_b64url}&encoding=base64"
    )
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        return json.loads(resp.content)


async def get_attestation_payload(nonce: str | None) -> dict | None:
    """Mint a fresh TDX quote with the nonce bound into REPORTDATA.

    Returns the JSON payload served by /v1/attestation, or None if the
    nonce is malformed. Raises on AA failure (caller maps to 502).
    """
    raw_nonce = _validate_nonce(nonce)
    if raw_nonce is None:
        return None

    # ITA-verifiable binding: REPORTDATA = SHA512(nonce) (64 B, zero-pad is
    # a no-op at exactly 64 bytes). The client later sends
    # runtime_data=<raw nonce> to ITA /attest; ITA re-hashes and compares.
    report_data = hashlib.sha512(raw_nonce.encode("ascii")).digest()
    report_data_b64url = (
        base64.urlsafe_b64encode(report_data).decode("ascii").rstrip("=")
    )

    evidence = await _aa_get_evidence(report_data_b64url)

    payload: dict[str, Any] = {
        "nonce": raw_nonce,
        "report_data_input": "sha512(nonce)",
        "quote": evidence.get("quote"),
        "cc_eventlog": evidence.get("cc_eventlog"),
        "tee": "tdx",
        "runtime_class": "kata-qemu-tdx-runtime-rs",
    }
    tls_proof = _tls_possession_proof(raw_nonce)
    if tls_proof is not None:
        payload["tls_possession"] = tls_proof
    pod = _pod_name()
    if pod:
        payload["pod"] = pod
    return payload


def _backend_identity_headers(
    data: dict, litellm_call_info: dict | None
) -> dict[str, str]:
    """Best-effort backend identity headers for inline evidence.

    Per the scope decision, backends are boot-time attested (Trustee-gated
    mTLS cert issuance) — we surface identity metadata only, not per-request
    GPU quotes.
    """
    headers: dict[str, str] = {}
    info = litellm_call_info or {}
    model_info = info.get("model_info") or {}
    model_id = info.get("model_id") or model_info.get("model_id")
    api_base = info.get("api_base") or model_info.get("api_base")

    model_name = None
    if isinstance(data, dict):
        model_name = data.get("model")
    if not model_name and isinstance(model_info, dict):
        model_name = model_info.get("model_name")

    if model_name or model_id:
        headers["X-KubeTEE-Backend"] = str(model_name or model_id)
    if api_base:
        headers["X-KubeTEE-Backend-Endpoint"] = str(api_base)
    headers["X-KubeTEE-Backend-Attested"] = "boot-time (Trustee EAR; east-west mTLS)"
    return headers


def _mount_attestation_route():
    """Add GET /v1/attestation to the LiteLLM FastAPI app.

    Idempotent (guarded by route scan). Same pattern as
    PrometheusLogger._mount_metrics_endpoint — LiteLLM mounts custom
    endpoints from callbacks without a server restart.
    """
    from fastapi import Query
    from fastapi.responses import JSONResponse
    from litellm.proxy.proxy_server import app

    path = "/v1/attestation"
    for route in getattr(app, "routes", []):
        if getattr(route, "path", None) == path:
            return  # already mounted (hot reload)

    async def attestation_endpoint(nonce: str = Query(...)):
        try:
            payload = await get_attestation_payload(nonce)
        except Exception as e:  # AA unreachable / quote failed
            return JSONResponse(
                status_code=502,
                content={"error": f"attestation evidence unavailable: {e}"},
            )
        if payload is None:
            return JSONResponse(
                status_code=400,
                content={"error": "nonce must be exactly 64 hex characters"},
            )
        return JSONResponse(content=payload)

    app.add_api_route(
        path=path,
        endpoint=attestation_endpoint,
        methods=["GET"],
        name="kubetee_attestation",
        tags=["kubetee"],
    )


def _mount_once():
    """Import-time route mount with defensive fallback.

    Litellm imports callbacks at proxy startup; the FastAPI `app` object
    exists by then (same pattern as PrometheusLogger._mount_metrics_endpoint
    — called from initialize_callbacks_on_proxy after app creation).
    """
    try:
        _mount_attestation_route()
    except Exception:
        # Never break the proxy because attestation route mounting failed.
        import traceback

        try:
            from litellm._logging import verbose_proxy_logger

            verbose_proxy_logger.error(
                "kubetee_attestation: route mount failed:\n%s",
                traceback.format_exc(),
            )
        except Exception:
            pass


class KubeTEEAttestationLogger(CustomLogger):
    """CustomLogger that mounts /v1/attestation and injects inline evidence.

    Only async_post_call_response_headers_hook is overridden. That hook is
    invoked BEFORE response headers freeze on BOTH the streaming and the
    non-streaming chat path in base_process_llm_request — unlike
    async_post_call_success_hook, which runs after the streaming
    StreamingResponse has already been constructed (headers fixed).
    """

    def __init__(self):
        super().__init__()
        _mount_once()

    async def async_post_call_response_headers_hook(
        self,
        data: dict,
        user_api_key_dict: Any,
        response: Any,
        request_headers: dict[str, str] | None = None,
        litellm_call_info: dict[str, Any] | None = None,
    ) -> dict[str, str] | None:
        """Opt-in inline TDX evidence on chat responses.

        Fires when the client sent X-KubeTEE-Nonce on the request. Returns
        X-KubeTEE-* headers that LiteLLM merges into the HTTP response.
        """
        headers = request_headers or {}
        nonce = None
        for k, v in headers.items():
            if k.lower() == _NONCE_HEADER:
                nonce = v
                break
        raw_nonce = _validate_nonce(nonce)
        if nonce is not None and raw_nonce is None:
            # Malformed nonce: signal, don't fail the completion.
            return {"X-KubeTEE-Attestation-Error": "invalid nonce (need 64 hex)"}
        if raw_nonce is None:
            return None  # opt-in header absent — no-op

        report_data = hashlib.sha512(raw_nonce.encode("ascii")).digest()
        report_data_b64url = (
            base64.urlsafe_b64encode(report_data).decode("ascii").rstrip("=")
        )
        try:
            evidence = await _aa_get_evidence(report_data_b64url)
            quote = evidence.get("quote")
        except Exception as e:
            return {"X-KubeTEE-Attestation-Error": f"quote unavailable: {e}"}

        if not quote:
            return {"X-KubeTEE-Attestation-Error": "empty quote"}

        out = {
            "X-KubeTEE-Nonce": raw_nonce,
            "X-KubeTEE-Attestation-Quote": quote,
            "X-KubeTEE-Attestation-Tee": "tdx",
        }
        tls_proof = _tls_possession_proof(raw_nonce)
        if tls_proof is not None:
            out["X-KubeTEE-TLS-Signature"] = tls_proof["tls_signature"]
            out["X-KubeTEE-TLS-Signature-Alg"] = "RS256"
            out["X-KubeTEE-TLS-Signature-Input"] = "sha256(nonce)"
            if tls_proof.get("tls_cert_sha256"):
                out["X-KubeTEE-TLS-Cert-SHA256"] = tls_proof["tls_cert_sha256"]
        out.update(_backend_identity_headers(data, litellm_call_info))
        return out


# Resolved by get_instance_fn("kubetee_attestation.kubetee_attestation_logger").
# Singleton instance (instantiated once; __init__ mounts the route).
kubetee_attestation_logger = KubeTEEAttestationLogger()
