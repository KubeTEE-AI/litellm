# KubeTEE client-facing AMD SEV-SNP attestation for the public gateway.
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
#    keyset, bindings, tls_possession, quote=null, cc_eventlog=null,
#    evidence: {snp: {schema, attestation_report, cert_chain}, vm_config},
#    appraisal: {ear_token, ar4si}}
#
# TDX top-level fields are retained for explicit protocol evolution only:
# on SNP they are null, and legacy quote-only clients cannot verify it.
# A client supporting SNP must branch on the typed evidence.snp schema.
# `report_data_input`
# names the active construction on every response.
#
# Inline evidence (opt-in): X-KubeTEE-Nonce on /v1/chat/completions puts
# X-KubeTEE-Attestation-SNP + the same binding/possession headers on the
# SAME response, binding proof to the serving replica.
#
# The binding — kubetee.attestation.v1 (spec section 4)
# ---------------------------------------------------------------------------
# REPORTDATA (64 B in the quote) = SHA-256(JCS(statement)) || 32 zero bytes
# for the fixed template:
#
#   {"keyset_digest":"sha256:<hex>","nonce":"<64-hex>","purpose":"kubetee.attestation.v1"}
#
# TDX REPORTDATA or SNP report_data. `report_data_input` names the
# construction on every response. SNP places its native structured evidence
# under `evidence.snp`; its AMD report is never a TDX quote. Both endpoints
# reject a TDX quote, wrong-platform evidence, or an invalid signed binding.
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
# statement). It appraises this SNP guest's measurements + initdata; the per-request
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
# (nonce + SNP evidence of THIS guest only).

import base64
import binascii
import hashlib
import json
import os
import re
import socket
from typing import Any
from urllib.parse import urlencode

import kubetee_binding
import kubetee_ear
from litellm.integrations.custom_logger import CustomLogger

SPEC_VERSION = "kubetee.attestation.v1"

# Construction switch: this gateway uses KUBETEE_ATTESTATION_V1=1 for the
# published v1 statement. Legacy SHA512(nonce) remains available only for an
# explicitly configured older consumer, with matching response metadata.
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
    signature proves the guest that minted the attestation payload also
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
    """Return native CoCo {attestation_report, cert_chain} evidence."""
    import httpx
    url = f"{_AA_BASE}/aa/evidence?{urlencode({'runtime_data': runtime_data_b64url, 'encoding': 'base64'})}"
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        return json.loads(resp.content)


# Gateway-only SNP producer; neither function nor configuration changes KBS.

class EvidenceError(RuntimeError):
    """The guest returned missing, malformed, or wrong-platform evidence."""


_TEE_RUNTIMES = {"tdx": "kata-qemu-tdx-runtime-rs", "snp": "kata-qemu-snp-runtime-rs"}


def _tee_type() -> str:
    """Select measured guest hardware; TDX remains the legacy default."""
    value = os.environ.get("KUBETEE_TEE", "tdx").strip().lower()
    # Explicit SNP spelling only. "sev"/"sev-es" are not an SNP fallback.
    value = "snp" if value == "sev-snp" else value
    if value not in _TEE_RUNTIMES:
        raise EvidenceError(f"unsupported KUBETEE_TEE: {value!r}")
    runtime = os.environ.get("KUBETEE_RUNTIME_CLASS", _TEE_RUNTIMES[value])
    if runtime != _TEE_RUNTIMES[value]:
        raise EvidenceError(f"KUBETEE_RUNTIME_CLASS conflicts with selected {value} platform")
    return value


TEE_TYPE = _tee_type()
RUNTIME_CLASS = os.environ.get("KUBETEE_RUNTIME_CLASS", _TEE_RUNTIMES[TEE_TYPE])


def _b64_bytes(value: Any, name: str) -> bytes:
    if isinstance(value, str):
        if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", value):
            raise EvidenceError(f"SNP {name} is not valid base64")
    else:
        raise EvidenceError(f"SNP {name} is missing or malformed")
    if not value:
        raise EvidenceError(f"SNP {name} is missing or malformed")
    try:
        return base64.b64decode(value.replace("-", "+").replace("_", "/") + "=" * (-len(value) % 4), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise EvidenceError(f"SNP {name} is not valid base64") from exc


def _snp_bytes(value: Any, name: str, size: int | None = None) -> bytes:
    """Decode CoCo's JSON u8 arrays; accept b64 only for alternate encodings."""
    if isinstance(value, list):
        if any(isinstance(b, bool) or not isinstance(b, int) or not 0 <= b <= 255 for b in value):
            raise EvidenceError(f"SNP {name} contains a non-byte value")
        raw = bytes(value)
    else:
        raw = _b64_bytes(value, name)
    if size is not None and len(raw) != size:
        raise EvidenceError(f"SNP {name} must be {size} bytes")
    return raw


def _snp_evidence(report: Any, cert_chain: Any, report_data: bytes) -> dict[str, Any]:
    """Pass CoCo's structured SnpEvidence; check binding and buffer shapes.

    Keep CoCo's structured AttestationReport rather than treating it as a
    TDX quote or inventing a Python serializer for all version-dependent fields.
    The optional certificate table is DER bytes, normally with at least VCEK;
    AMD root/flash-resident certificate absence is not forged here.
    """
    if not isinstance(report, dict):
        raise EvidenceError("SNP attestation_report must be the native CoCo structured JSON object; raw strings are not supported")
    version = report.get("version", 3)
    if isinstance(version, bool) or not isinstance(version, int) or not 3 <= version <= 5:
        raise EvidenceError(f"unsupported SNP report version: {version!r}")
    if isinstance(report.get("vmpl"), bool) or report.get("vmpl", 0) != 0:
        raise EvidenceError("SNP VMPL0 is required")
    for field in ("current_tcb", "reported_tcb"):
        value = report.get(field)
        # Optional processor-generation fields (e.g. Venice's absent boot SVNs)
        # are null in CoCo JSON; required tee/snp are numeric u8 values.
        if not isinstance(value, dict) or any(
            isinstance(value.get(k), bool) or not isinstance(value.get(k), int) or not 0 <= value[k] <= 255
            for k in ("snp", "tee")
        ):
            raise EvidenceError(f"SNP {field} must carry numeric snp/tee fields")
    if report.get("sig_algo", 1) != 1:
        raise EvidenceError("SNP report must use ECDSA P-384")
    if _snp_bytes(report.get("report_data"), "report_data", 64) != report_data:
        raise EvidenceError("SNP signed report_data does not match the served binding")
    for name, size in (("measurement", 48), ("host_data", 32), ("family_id", 16), ("image_id", 16)):
        _snp_bytes(report.get(name), name, size)
    sig = report.get("signature")
    if not isinstance(sig, dict):
        raise EvidenceError("SNP signature must be an object containing r and s")
    for name in ("r", "s"):
        _snp_bytes(sig.get(name), f"signature.{name}", 72)
    if cert_chain is None:
        cert_chain = []
    if not isinstance(cert_chain, list):
        raise EvidenceError("SNP cert_chain must be a list")
    if len(cert_chain) > 64:
        raise EvidenceError("SNP certificate table exceeds protocol bounds")
    if len(json.dumps(report, separators=(",", ":"))) > 64 * 1024:
        raise EvidenceError("SNP structured report exceeds protocol bounds")
    for entry in cert_chain:
        # CoCo's Linux ABI may label certificate entries OTHER; labels do not
        # authenticate the VCEK/ASK/ARK chain.
        if not isinstance(entry, dict) or not isinstance(entry.get("cert_type"), str):
            raise EvidenceError("SNP cert_chain entries must have a cert_type string")
        if not _snp_bytes(entry.get("data"), "certificate DER"):
            raise EvidenceError("SNP certificate is empty")
    # This is the protocol discriminator consumed by gm-miner, not a claim of
    # AMD trust. The latter is established only by VCEK/report verification.
    return {
        "schema": "kubetee.snp-evidence/1",
        "attestation_report": report,
        "cert_chain": cert_chain,
    }


def _hardware_evidence(evidence: Any, report_data: bytes) -> dict[str, Any]:
    """Return the selected platform's native signed evidence, fail closed."""
    if not isinstance(evidence, dict):
        raise EvidenceError("AA did not return an evidence object")
    if evidence.get("error"):
        raise EvidenceError(f"AA evidence unavailable: {evidence['error']}")
    if TEE_TYPE == "snp":
        # The documented CoCo SNP AA response is itself an evidence object,
        # unlike the Intel wrapper's `quote` field. Accept only the explicit
        # `snp` wrapper as an alternate, never Intel native evidence.
        if set(evidence) == {"snp"} and isinstance(evidence["snp"], dict):
            evidence = evidence["snp"]
        if evidence.get("quote") is not None:
            raise EvidenceError("TDX quote supplied for an SNP guest")
        report = evidence.get("attestation_report")
        if report is None:
            raise EvidenceError("SNP evidence unavailable: attestation_report is absent")
        return _snp_evidence(report, evidence.get("cert_chain"), report_data)
    if evidence.get("attestation_report") is not None:
        raise EvidenceError("SNP evidence supplied for a TDX guest")
    # Preserve the proven TDX arm unchanged; only its platform discriminator
    # becomes dynamic. SNP hardware verification is tested independently.
    if not isinstance(evidence.get("quote"), str) or not evidence["quote"]:
        raise EvidenceError("TDX quote unavailable")
    return {"quote": evidence["quote"], "cc_eventlog": evidence.get("cc_eventlog")}


def _report_data_from_payload(payload: dict[str, Any], nonce: str) -> bytes:
    """Extract the hardware-bound input from the v1 response, not labels."""
    if not isinstance(payload.get("bindings"), dict):
        raise EvidenceError("v1 payload has no keyset/nonce binding statement")
    statement = payload["bindings"].get("report_data_statement")
    if not isinstance(statement, str):
        raise EvidenceError("v1 report_data_statement is absent")
    return kubetee_binding.report_data(statement)


def _attestation_headers(payload: dict[str, Any], nonce: str) -> dict[str, str]:
    """Same evidence as /v1/attestation, expressed as inline HTTP headers."""
    tee = payload["tee"]
    out = {
        "X-KubeTEE-Nonce": nonce,
        "X-KubeTEE-Attestation-Tee": tee,
        "X-KubeTEE-Runtime-Class": payload["runtime_class"],
        "X-KubeTEE-Report-Data-Input": payload["report_data_input"],
        "X-KubeTEE-Attestation-Report-Data": base64.b64encode(
            _report_data_from_payload(payload, nonce) if payload["report_data_input"] == kubetee_binding.PURPOSE
            else kubetee_binding.legacy_report_data(nonce)
        ).decode("ascii"),
    }
    if tee == "snp":
        # AMD is a separate schema, not bytes in the Intel quote header.
        snp_evidence = (payload.get("evidence") or {}).get("snp")
        if not isinstance(snp_evidence, dict):
            raise EvidenceError("SNP payload lacks typed native evidence")
        # Base64url preserves exact native CoCo JSON through HTTP encoders.
        encoded = json.dumps(snp_evidence, separators=(",", ":"), sort_keys=True).encode("utf-8")
        if len(encoded) > 24 * 1024:
            raise EvidenceError("SNP evidence exceeds inline transport budget; use /v1/attestation")
        out["X-KubeTEE-Attestation-SNP"] = base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("=")
        out["X-KubeTEE-Attestation-SNP-Encoding"] = "base64url-json"
    elif tee == "tdx":
        out["X-KubeTEE-Attestation-Quote"] = payload["quote"]
        if payload.get("cc_eventlog"):
            if isinstance(payload["cc_eventlog"], list):
                out["X-KubeTEE-Attestation-Event-Log"] = json.dumps(payload["cc_eventlog"], separators=(",", ":"))
            else:
                out["X-KubeTEE-Attestation-Event-Log"] = payload["cc_eventlog"]
    else:
        raise EvidenceError(f"unsupported evidence platform: {tee}")
    if V1_MODE:
        bindings = payload["bindings"]
        out["X-KubeTEE-Binding-Statement"] = bindings["report_data_statement"]
        out["X-KubeTEE-Binding-Keyset-Digest"] = bindings["keyset_digest"]
    tls_proof = payload.get("tls_possession")
    if tls_proof:
        out["X-KubeTEE-TLS-Signature"] = tls_proof["tls_signature"]
        out["X-KubeTEE-TLS-Signature-Alg"] = tls_proof["tls_signature_alg"]
        out["X-KubeTEE-TLS-Signature-Input"] = tls_proof["tls_signature_input"]
        if tls_proof.get("tls_cert_sha256"):
            out["X-KubeTEE-TLS-Cert-SHA256"] = tls_proof["tls_cert_sha256"]
    return out


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
    """Mint fresh AMD SEV-SNP evidence for this gateway request."""
    raw_nonce = _validate_nonce(nonce)
    if raw_nonce is None:
        return None
    if V1_MODE:
        keyset, binding = _binding_for_nonce(raw_nonce)
        report_data = binding.report_data
    else:
        keyset = binding = None
        report_data = kubetee_binding.legacy_report_data(raw_nonce)
    runtime_data = base64.urlsafe_b64encode(report_data).decode("ascii").rstrip("=")
    raw_evidence = await _aa_get_evidence(runtime_data)
    platform_evidence = _hardware_evidence(raw_evidence, report_data)
    payload: dict[str, Any] = {
        "nonce": raw_nonce, "report_data_input": REPORT_DATA_INPUT,
        "quote": platform_evidence["quote"] if TEE_TYPE == "tdx" else None,
        "cc_eventlog": platform_evidence.get("cc_eventlog") if TEE_TYPE == "tdx" else None,
        "tee": TEE_TYPE, "runtime_class": RUNTIME_CLASS,
    }
    tls_proof = _tls_possession_proof(raw_nonce)
    if tls_proof is not None:
        payload["tls_possession"] = tls_proof
    if pod := _pod_name():
        payload["pod"] = pod
    if V1_MODE:
        payload.update({
            "spec_version": SPEC_VERSION, "tee_type": TEE_TYPE, "keyset": keyset,
            "bindings": {"version": binding.version,
                "report_data_statement": binding.statement,
                "keyset_digest": binding.keyset_digest},
            "evidence": {
                "quote": payload["quote"],
                "quote_report_data": base64.b64encode(report_data).decode("ascii"),
                "event_log": payload["cc_eventlog"], "vm_config": kubetee_ear.vm_config(),
            },
        })
        if TEE_TYPE == "snp":
            payload["evidence"]["snp"] = {"schema": "kubetee.snp-evidence/1", **platform_evidence}
        appraisal = kubetee_ear.appraisal(kubetee_ear.load_cached_ear())
        if appraisal is not None:
            payload["appraisal"] = appraisal
    elif TEE_TYPE == "snp":
        payload["evidence"] = {"snp": {"schema": "kubetee.snp-evidence/1", **platform_evidence}, "quote_report_data": base64.b64encode(report_data).decode("ascii")}
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
        """Opt-in inline AMD SEV-SNP evidence on chat responses.

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

        try:
            payload = await get_attestation_payload(raw_nonce)
            if payload is None:
                return {"X-KubeTEE-Attestation-Error": "invalid nonce (need 64 hex)"}
            out = _attestation_headers(payload, raw_nonce)
        except Exception as e:
            return {"X-KubeTEE-Attestation-Error": f"attestation evidence unavailable: {e}"}
        out.update(_backend_identity_headers(data, litellm_call_info))
        return out


# Resolved by get_instance_fn("kubetee_attestation.kubetee_attestation_logger").
# Singleton instance (instantiated once; __init__ mounts the route).
kubetee_attestation_logger = KubeTEEAttestationLogger()
