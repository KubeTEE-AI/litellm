# KubeTEE client-facing attestation for the LiteLLM gateway (CPU TDX guest).
#
# Baked into the litellm-database overlay image (site-packages), loaded as a
# custom callback:
#   callbacks: ["dynamic_rate_limiter_v3", "prometheus",
#               "kubetee_attestation.kubetee_attestation_logger"]
#
# The surface (kubetee-subnet/docs/ATTESTATION-SPEC-v1.md is the contract)
# ---------------------------------------------------------------------------
# GET /v1/attestation?nonce=<64 hex> returns the v1 bundle:
#
#   {spec_version, tee_type, nonce, report_data_input, pod, quote, cc_eventlog,
#    keyset, bindings, tls_possession,                <- legacy top level
#    evidence: {quote, quote_report_data, event_log, vm_config},
#    appraisal: {ear_token, ar4si}}
#
# The legacy top-level fields stay for the dual-read window: gm-miner's
# shipped AttestationPayload (evidence.rs) parses quote / cc_eventlog /
# tls_possession at the top level with strict serde and drops unknown fields,
# so the v1 shape is ADDITIVE until that window closes. `report_data_input`
# names the active construction on every response.
#
# Inline evidence (opt-in): X-KubeTEE-Nonce on /v1/chat/completions puts
# X-KubeTEE-Attestation-Quote + the same binding/possession headers on the
# SAME response, binding proof to the serving replica.
#
# The binding — kubetee.attestation.v1 (spec section 4)
# ---------------------------------------------------------------------------
# REPORTDATA (64 B in the quote) = SHA-256(JCS(statement)) || 32 zero bytes
# for the fixed template:
#
#   {"keyset_digest":"sha256:<hex>","nonce":"<64-hex>","purpose":"kubetee.attestation.v1"}
#
# This is the v1 construction — NOT the wire default yet. Until the gm-miner
# switch PR (taostat/gm-miner, kubetee_verify) is accepted upstream AND
# gm-miner is redeployed, the quote stays bound to the legacy SHA512(nonce)
# construction the deployed verifier checks, and the response carries NO
# keyset/bindings (binding claims appear only with the v1 binding — the
# verifier fails mixed shapes closed). `report_data_input` names the active
# construction on every response ("sha512(nonce)" default). Flip with
# KUBETEE_ATTESTATION_V1=1 after the switch: the v1 statement then binds the
# quote (travels verbatim as bindings.report_data_statement — no
# reconstruction ambiguity), keyset_digest covers the served keyset, and the
# v1 bundle (evidence/appraisal) rides along.
#
# TLS possession (both surfaces)
# ---------------------------------------------------------------------------
# llm.kubetee.ai is TLS PASSTHROUGH — the client's TLS session terminates
# INSIDE this guest. Both surfaces sign the nonce with this pod's serving
# key — the cert-manager litellm-tls key (RS256) or, where a per-boot
# in-guest key is configured via KUBETEE_TLS_KEY, that P-256 key (ES256).
# The client verifies against the leaf from its OWN TLS session, so the quote
# is pinned to the exact serving pod. `tls_signature_alg` names the algorithm
# actually used — gm-miner accepts both and fails closed on any other or on
# a key-type mismatch.
#
# Appraisal (spec section 1 — the EAR/AR4SI results leg)
# ---------------------------------------------------------------------------
# `appraisal.ear_token` is a Trustee EAR minted ONCE PER BOOT over the RCAR
# binding (its own hash — see kubetee_ear.py for why it is not the v1
# statement). It appraises this TD's measurements + initdata; the per-request
# nonce binding is the v1 statement's job. `appraisal.ar4si` exposes the
# trustworthiness vector plus the partner claim mapping so adapters never
# parse the JWT by hand. Absent (field omitted) when Trustee is unreachable —
# the quote and binding stand alone.
#
# Key custody (spec section 5)
# ---------------------------------------------------------------------------
# The client-facing serving key is the cert-manager litellm-tls key
# (Kubernetes Secret — an admin-readable Secret is the accepted posture for
# the PUBLIC TLS surface; the quote + possession proof pin the pod). Strict
# per-boot in-TEE key custody lives on the EAST-WEST identity: a per-boot
# P-256 key certified only through the attestation-gated signer whose EAR
# binds its tee-pubkey. The keyset's tls_public_keys[].spki_sha256 is the
# serving key's SPKI digest, bound into REPORTDATA via keyset_digest.
#
# Auth: LiteLLM attaches user_api_key_auth to routes it knows; a custom
# app.add_api_route endpoint does NOT get the auth dependency by default —
# it is public on the guest network. The endpoint discloses no secrets
# (nonce + TDX quote of THIS guest only).

import base64
import hashlib
import os
import re
import socket
from typing import Any

import kubetee_binding
from litellm.integrations.custom_logger import CustomLogger

SPEC_VERSION = "kubetee.attestation.v1"
TEE_TYPE = "tdx"
RUNTIME_CLASS = "kata-qemu-tdx-runtime-rs"

# Construction switch (see header): legacy SHA512(nonce) is the wire default
# while the deployed gm-miner verifies it; KUBETEE_ATTESTATION_V1=1 flips the
# quote binding to the v1 statement AFTER the gm-miner switch PR is accepted
# and redeployed. The response shape follows the switch atomically: v1
# (keyset/bindings/evidence/appraisal) or the exact legacy shape.
V1_MODE = os.environ.get("KUBETEE_ATTESTATION_V1", "").strip().lower() in ("1", "true", "yes", "on")
REPORT_DATA_INPUT = "kubetee.attestation.v1" if V1_MODE else kubetee_binding.LEGACY_REPORT_DATA_INPUT

_NONCE_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_AA_BASE = os.environ.get("KUBETEE_AA_BASE", "http://127.0.0.1:8006")
_NONCE_HEADER = "x-kubetee-nonce"
_TLS_DIR = os.environ.get("KUBETEE_TLS_DIR", "/etc/tls")
_TLS_KEY_PATH = os.environ.get("KUBETEE_TLS_KEY", os.path.join(_TLS_DIR, "tls.key"))
_TLS_CERT_PATH = os.environ.get("KUBETEE_TLS_CERT", os.path.join(_TLS_DIR, "tls.crt"))
_TLS_DOMAIN = os.environ.get("KUBETEE_TLS_DOMAIN", "llm.kubetee.ai")


def _pod_name() -> str | None:
    try:
        return os.environ.get("POD_NAME") or socket.gethostname()
    except Exception:
        return None


def _validate_nonce(nonce: str | None) -> str | None:
    """Return the normalized (lowercased) nonce or None if malformed."""
    if not nonce:
        return None
    nonce = nonce.strip()
    if not _NONCE_RE.match(nonce):
        return None
    return nonce.lower()


def _load_serving_key():
    """The serving key, or None. cert-manager litellm-tls (RS256) by
    default; an EC P-256 override via KUBETEE_TLS_KEY signs ES256."""
    try:
        from cryptography.hazmat.primitives import serialization

        with open(_TLS_KEY_PATH, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    except Exception:
        return None


def _tls_possession_proof(nonce: str) -> dict | None:
    """Sign the nonce with the pod's TLS private key (POSSESSION proof).

    The client verifies the signature against the leaf certificate from ITS
    OWN TLS session (llm.kubetee.ai terminates inside this guest). A valid
    signature proves the TDX guest that minted the attestation payload also
    holds the private key of the cert the client is connected to — binding
    the quote to the exact serving pod, not just "some gateway replica".

    The algorithm is reported, not assumed: the per-boot key is EC P-256 and
    signs ES256 (ECDSA over SHA-256, ASN.1 DER signature); a legacy RSA key
    signs RS256 (RSASSA-PKCS1-v1_5 over SHA-256). Both are one line of code
    in cryptography and one verify call in gm-miner.

    Returns {"tls_signature": b64, "tls_signature_alg": "ES256"|"RS256",
             "tls_signature_input": "sha256(nonce)", "tls_cert_sha256": hex}
    or None if the key is unavailable (best-effort; the quote is still the
    primary evidence).
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, padding, utils

        key = _load_serving_key()
        if key is None:
            return None

        if isinstance(key, ec.EllipticCurvePrivateKey):
            # ES256: ECDSA over SHA-256. JWS/ES256 uses raw r||s, but the
            # spec's verifier contract (and gm-miner) verify the ASN.1 DER
            # signature that cryptography produces natively — same bytes
            # a TLS stack would present. Report "ES256" + DER.
            der = key.sign(nonce.encode("ascii"), ec.ECDSA(hashes.SHA256()))
            # Normalize to JOSE raw r||s (64 bytes) for wire-format
            # predictability; gm-miner decodes DER or raw.
            r, s = utils.decode_dss_signature(der)
            size = key.curve.key_size // 8
            sig = r.to_bytes(size, "big") + s.to_bytes(size, "big")
            alg = "ES256"
        else:
            # Legacy RSA path (a cert-manager-era key). RS256 semantics:
            # signature over SHA256(nonce).
            sig = key.sign(
                nonce.encode("ascii"),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            alg = "RS256"

        cert_fp: str | None = None
        try:
            from cryptography.hazmat.primitives.serialization import Encoding

            with open(_TLS_CERT_PATH, "rb") as f:
                cert_pem = f.read()
            # tls.crt carries the full chain (leaf + intermediates); the
            # client fingerprint is of the LEAF (first cert in the file,
            # and the one its TLS session serves). Hash only that.
            first_pem = (
                cert_pem.split(b"-----END CERTIFICATE-----")[0]
                + b"-----END CERTIFICATE-----"
            )
            der = x509.load_pem_x509_certificate(first_pem).public_bytes(Encoding.DER)
            cert_fp = hashlib.sha256(der).hexdigest()
        except Exception:
            pass
        return {
            "tls_signature": base64.b64encode(sig).decode("ascii"),
            "tls_signature_alg": alg,
            "tls_signature_input": "sha256(nonce)",
            "tls_cert_sha256": cert_fp,
        }
    except Exception:
        return None


def _binding_bundle(
    nonce: str,
) -> tuple[dict[str, kubetee_binding.JsonTree], kubetee_binding.Binding] | None:
    """Served keyset (spec section 5) + v1 binding for this nonce, or None.

    Mandatory at the gateway flip: a response without a binding is a bug, so
    the caller logs and omits only when the key material is unreadable (the
    possession proof degrades the same way).
    """
    try:
        with open(_TLS_CERT_PATH, "rb") as f:
            cert_pem = f.read()
        keyset = kubetee_binding.keyset_from_cert_pem(cert_pem, _TLS_DOMAIN)
    except Exception:
        return None
    return keyset, kubetee_binding.build_binding(keyset, nonce)


async def _aa_get_evidence(runtime_data_b64url: str) -> dict:
    """Call in-guest /aa/evidence; parse the TdxEvidence JSON envelope.

    Returns {"quote": <b64 str>, "cc_eventlog": <b64 str|None>} or raises.
    The AA returns JSON bytes (content-type is octet-stream, cosmetic).
    """
    import httpx

    url = f"{_AA_BASE}/aa/evidence?runtime_data={runtime_data_b64url}&encoding=base64"
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        import json as _json

        return _json.loads(resp.content)


def _binding_for_nonce(nonce: str) -> tuple[dict, kubetee_binding.Binding]:
    """The served keyset + v1 binding for a nonce, or raise.

    Fail-closed: rather than emit a quote with an unbound REPORTDATA (the
    flip made the binding mandatory), missing key material raises and the
    caller maps it to an error response.
    """
    bundle = _binding_bundle(nonce)
    if bundle is None:
        raise RuntimeError("serving key material unavailable for the v1 binding")
    return bundle


async def get_attestation_payload(nonce: str | None) -> dict | None:
    """Mint a fresh TDX quote with the active construction bound into REPORTDATA.

    Returns the JSON payload served by /v1/attestation — the exact legacy
    shape (the deployed gm-miner's contract) by default, or the v1 bundle
    under KUBETEE_ATTESTATION_V1=1 — or None if the nonce is malformed.
    Raises on AA failure (caller maps to 502).
    """
    raw_nonce = _validate_nonce(nonce)
    if raw_nonce is None:
        return None

    if V1_MODE:
        keyset, binding = _binding_for_nonce(raw_nonce)
        report_data = binding.report_data
    else:
        keyset = binding = None
        report_data = kubetee_binding.legacy_report_data(raw_nonce)
    report_data_b64url = (
        base64.urlsafe_b64encode(report_data).decode("ascii").rstrip("=")
    )
    evidence = await _aa_get_evidence(report_data_b64url)

    payload: dict[str, Any] = {
        "nonce": raw_nonce,
        "report_data_input": REPORT_DATA_INPUT,
        "quote": evidence.get("quote"),
        "cc_eventlog": evidence.get("cc_eventlog"),
        "tee": TEE_TYPE,
        "runtime_class": RUNTIME_CLASS,
    }
    tls_proof = _tls_possession_proof(raw_nonce)
    if tls_proof is not None:
        payload["tls_possession"] = tls_proof
    pod = _pod_name()
    if pod:
        payload["pod"] = pod

    if V1_MODE:
        payload["spec_version"] = SPEC_VERSION
        payload["tee_type"] = TEE_TYPE
        payload["keyset"] = keyset
        payload["bindings"] = {
            "version": binding.version,
            "report_data_statement": binding.statement,
            "keyset_digest": binding.keyset_digest,
        }
        # --- v1 spec bundle ---
        import kubetee_ear

        payload["evidence"] = {
            "quote": evidence.get("quote"),
            "quote_report_data": base64.b64encode(report_data).decode("ascii"),
            "event_log": evidence.get("cc_eventlog"),
            "vm_config": kubetee_ear.vm_config(),
        }
        appraisal = kubetee_ear.appraisal(kubetee_ear.load_cached_ear())
        if appraisal is not None:
            payload["appraisal"] = appraisal
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
        litellm_call_info: dict[str, str] | None = None,
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

        if V1_MODE:
            try:
                _keyset, binding = _binding_for_nonce(raw_nonce)
            except Exception as e:
                return {"X-KubeTEE-Attestation-Error": f"binding unavailable: {e}"}
            report_data = binding.report_data
        else:
            binding = None
            report_data = kubetee_binding.legacy_report_data(raw_nonce)
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
            "X-KubeTEE-Attestation-Tee": TEE_TYPE,
            "X-KubeTEE-Report-Data-Input": REPORT_DATA_INPUT,
        }
        if V1_MODE:
            out["X-KubeTEE-Binding-Statement"] = binding.statement
            out["X-KubeTEE-Binding-Keyset-Digest"] = binding.keyset_digest
        tls_proof = _tls_possession_proof(raw_nonce)
        if tls_proof is not None:
            out["X-KubeTEE-TLS-Signature"] = tls_proof["tls_signature"]
            out["X-KubeTEE-TLS-Signature-Alg"] = tls_proof["tls_signature_alg"]
            out["X-KubeTEE-TLS-Signature-Input"] = tls_proof["tls_signature_input"]
            if tls_proof.get("tls_cert_sha256"):
                out["X-KubeTEE-TLS-Cert-SHA256"] = tls_proof["tls_cert_sha256"]
        out.update(_backend_identity_headers(data, litellm_call_info))
        return out


# Resolved by get_instance_fn("kubetee_attestation.kubetee_attestation_logger").
# Singleton instance (instantiated once; __init__ mounts the route).
kubetee_attestation_logger = KubeTEEAttestationLogger()
