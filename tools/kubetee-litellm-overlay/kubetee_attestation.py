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

import asyncio
import base64
import binascii
import datetime
import hashlib
import json
import os
import re
import socket
import time
from typing import Any, Final
from urllib.parse import urlencode

import kubetee_binding
import kubetee_ear
import kubetee_proof
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
_PROOF_HEADER = "x-kubetee-proof"

# Fresh-mint rate limit for the X-KubeTEE-Nonce path only (one silicon mint per
# request is expensive + serializes one-at-a-time; see the Phase 4b timing
# matrix). X-KubeTEE-Proof is the unlimited proof-of-inference alternative.
_FRESH_MINT_LIMIT: Final[int] = int(os.environ.get("KUBETEE_FRESH_MINT_LIMIT", "1"))
_FRESH_MINT_WINDOW_S: Final[float] = float(os.environ.get("KUBETEE_FRESH_MINT_WINDOW_S", "60"))
_fresh_mint_limiter = kubetee_proof.FreshMintLimiter(_FRESH_MINT_LIMIT, _FRESH_MINT_WINDOW_S)
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


# ---------------------------------------------------------------------------
# Backend evidence cache — shared across keys, never per key
# ---------------------------------------------------------------------------
# The backend (sglang) guest mints its own evidence at most once per epoch and
# this module RELAYS it. The cache is keyed by backend endpoint (a serving
# pod's api_base) and shared by EVERY API key on the gateway: a warm lookup is
# a dict read with no I/O and no key material involved. A cold or expired
# entry costs exactly ONE fetch under a per-endpoint asyncio.Lock (single
# flight: N concurrent first requests mint one quote, not N). Nothing here
# reads `user_api_key_dict`, and no key gets its own quote.
#
# The serving rule is the user's, literally: **serve the last quote if it is
# under `KUBETEE_BACKEND_QUOTE_TTL_S` old (default 300 s = 5 min)**. Past that
# we refetch; if the refetch fails we do NOT serve the stale quote — we fall
# back to the boot-time boundary label and say so
# (`X-KubeTEE-Backend-Evidence-Error`). Fail closed: never fabricate evidence
# and never present a quote as fresh outside its epoch.
#
# The per-request caller binding (a signature over
# sha256(quote)||sha256(nonce)||epoch_id made with the BACKEND's key) cannot be
# produced here — LiteLLM does not hold the backend's key. It rides along from
# the backend with the quote (see `_normalize_backend_evidence`), minted once
# per epoch alongside it.
_BACKEND_QUOTE_TTL_S: Final[float] = float(
    os.environ.get("KUBETEE_BACKEND_QUOTE_TTL_S", "300")
)
_BACKEND_ATTEST_PATH: Final[str] = os.environ.get(
    "KUBETEE_BACKEND_ATTEST_PATH", "/kubetee/evidence"
)
_BACKEND_ROLE: Final[str] = os.environ.get("KUBETEE_BACKEND_ROLE", "nim-terminator")
_BACKEND_QUOTE_MAX: Final[int] = int(os.environ.get("KUBETEE_BACKEND_QUOTE_MAX", "32"))
_BACKEND_EVIDENCE_MAX_HEADER_CHARS: Final[int] = int(
    os.environ.get("KUBETEE_BACKEND_EVIDENCE_MAX_HEADER_CHARS", "24000")
)
# Normative Layer-2 signature-input recipe, self-describing so a verifier
# never has to guess the byte layout (matches the backend signer's
# `signature_input()` exactly): concatenation of
#   SHA-256(quote_bytes)                32B  = the relayed `quote_sha256`
#   SHA-256(bytes.fromhex(nonce_hex))   32B  (nonce = 32B from a 64-hex string)
#   epoch_id.encode("ascii")           var
#   counter.to_bytes(8, "big")           8B
# signed Ed25519 (RFC 8032) by `tee_pubkey`. The nonce defeats quote reuse
# across callers; the counter defeats within-epoch replay.
_LAYER2_SIGNATURE_INPUT: Final[str] = (
    "ed25519(RFC8032) over "
    "sha256(quote_bytes)||sha256(bytes.fromhex(nonce_64hex))||"
    "epoch_id.encode('ascii')||counter.to_bytes(8,'big')"
)

# --- Reference registry (the CLIENT-FACING allowlist) -----------------------
# The backend's live TDX registers are matched against the SIGNED reference
# registry `kubetee.ai/.well-known/tee-measurements-registry.json`
# (schema `kubetee.tee-measurements-registry/1`), NOT against one pinned set.
# A record that matches ANY active record is approved; every record carries its
# own `valid_until` (90-day horizon) so a record outside its window is treated
# as deprecated and the matcher moves to the next — matching the client-facing
# `policy.match = any-active-record` contract in CLIENT-FACING-ATTESTATION.md.
# The registry is Ed25519-signed (RFC 8785 over the doc minus `signature`); the
# pinned PUBLIC key lives here (public keys are not secrets). With the default
# verification PUBLIC key unset, the registry is still matched but the
# signature is not checked.
_REGISTRY_URL: Final[str] = os.environ.get(
    "KUBETEE_REGISTRY_URL",
    "https://kubetee.ai/.well-known/tee-measurements-registry.json",
)
_REGISTRY_PUBLIC_KEY_B64: Final[str] = os.environ.get("KUBETEE_REGISTRY_PUBLIC_KEY", "")
_REGISTRY_CACHE_TTL_S: Final[float] = float(os.environ.get("KUBETEE_REGISTRY_CACHE_TTL_S", "300"))
_REGISTRY_TIMEOUT_S: Final[float] = float(os.environ.get("KUBETEE_REGISTRY_TIMEOUT_S", "15"))
_RECORD_FIELDS: Final[tuple[str, ...]] = (
    "mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3", "mrconfigid",
)

_registry_cache: dict[str, Any] | None = None
_registry_cache_monotonic: float = 0.0

_backend_quotes: dict[str, dict[str, Any]] = {}
_backend_quote_locks: dict[str, asyncio.Lock] = {}
_backend_quote_stats: dict[str, int] = {
    "hit": 0,
    "miss": 0,
    "fetch_error": 0,
    "fresh_nonce": 0,
}


def _eastwest_client_material() -> tuple[str, str] | None:
    """(client_cert_path, ca_path) for strict east-west mTLS, or None.

    Layout owned by kubetee_eastwest.fetch_eastwest(): `client.pem` is the
    concatenated cert+key, `ca.pem` is the east-west trust anchor. Present in
    the gateway's container-local scratch (`/run/kubetee-eastwest`) — not the
    host-shared `/certs`. Absent material means we cannot prove our identity
    to the backend's strict mTLS listener, so we return None and the fetch
    fails closed rather than downgrading to plaintext.
    """
    import kubetee_eastwest

    directory = kubetee_eastwest.EASTWEST_DIR
    cert = os.path.join(directory, "client.pem")
    ca = os.path.join(directory, "ca.pem")
    if os.path.exists(cert) and os.path.exists(ca):
        return cert, ca
    return None


def _backend_attest_url(api_base: str) -> str:
    """The backend's evidence endpoint.

    Deliberately NOT `/v1/attestation` — that path is the **gateway's** evidence
    surface (`_mount_attestation_route`) and stays gateway-only. The backend
    serves its own role-scoped route on its strict-mTLS listener, here
    The backend serves its role-scoped route at the **root** of its strict-mTLS
    listener, NOT under `/v1` (which the guest's /v1 router reserves for the
    OpenAI surface). `api_base` ends in `/v1`, so the `/v1` segment is STRIPPED
    before appending `_BACKEND_ATTEST_PATH` — otherwise we request
    `<api_base>/v1/kubetee/evidence`, which 404s (verified live 2026-11-25:
    `/kubetee/evidence` -> HTTP 200, `/v1/kubetee/evidence` -> HTTP 404). An
    `api_base` without a trailing `/v1` is used as-is.
    """
    base = api_base.rstrip("/")
    if base.endswith("/v1"):
        base = base[: -len("/v1")]
    return base + _BACKEND_ATTEST_PATH


def _normalize_backend_evidence(
    raw: Any, api_base: str, nonce: str | None = None
) -> dict[str, Any] | None:
    """Project the backend's evidence onto a self-describing envelope.

    The client does not know (and must not have to guess) whether the backend
    is TDX or SNP, so this normalizes BOTH into one envelope whose `schema`,
    `tee` and `role` fields discriminate. A TDX backend yields
    `schema: kubetee.tdx-evidence/1` with a `quote`; an SNP backend yields
    `schema: kubetee.snp-evidence/1` with native `snp`. The role is always
    `nim-terminator`, which is what distinguishes this from the gateway's own
    evidence — a TEE name alone cannot.

    The backend's mint-time signature over the quote is carried through
    verbatim (`signature`) — this module relays it and never re-signs, because
    it does not hold the backend's key.
    """
    if not isinstance(raw, dict):
        return None
    evidence = raw.get("evidence") if isinstance(raw.get("evidence"), dict) else {}
    tee = (raw.get("tee") or raw.get("tee_type") or "").strip().lower()
    if tee not in ("tdx", "snp"):
        # Infer only if the payload leaves it implicit; never guess wrong.
        tee = "tdx" if (raw.get("quote") or evidence.get("quote")) else "snp"

    quote = raw.get("quote") or evidence.get("quote")
    if quote is not None and not isinstance(quote, str):
        quote = base64.b64encode(bytes(quote)).decode("ascii")

    snp = evidence.get("snp")
    if tee == "snp" and snp is not None and quote is None:
        # SNP: carry the native structured report; `quote` stays empty.
        quote = None

    if tee == "tdx" and not quote:
        return None  # a TDX backend must actually yield a quote
    if tee == "snp" and snp is None and not quote:
        return None  # an SNP backend must yield a native report

    # quote_sha256 over the canonical evidence bytes actually served.
    if quote is not None:
        digest_src = base64.b64decode(quote + "=" * (-len(quote) % 4))
    else:
        digest_src = json.dumps(snp, separators=(",", ":"), sort_keys=True).encode("utf-8")

    epoch = {
        "id": raw.get("epoch_id") or (raw.get("bindings") or {}).get("epoch_id") or "",
        "issued_at": raw.get("issued_at") or "",
        "valid_until": raw.get("valid_until") or "",
    }
    schema = f"kubetee.{'tdx' if tee == 'tdx' else 'snp'}-evidence/1"
    signature = raw.get("backend_signature") or raw.get("signature")
    counter = raw.get("counter")
    out: dict[str, Any] = {
        "subject": "nim-terminator",
        "schema": schema,
        "tee": tee,
        "role": raw.get("role") or _BACKEND_ROLE,
        "runtime_class": raw.get("runtime_class") or "",
        "epoch": epoch,
        "quote": quote,
        "report_data": evidence.get("quote_report_data") or raw.get("report_data"),
        # The exact bytes hashed into report_data. SHARED-epoch path: an EPOCH
        # statement (identical for every caller in the epoch — NOT any caller's
        # nonce). FRESH nonce path: the per-caller nonce-derived statement. Either
        # way it is served verbatim so a caller verifies
        # SHA-256(report_data_statement) || 32 zeros against report_data without
        # re-deriving it.
        "report_data_statement": (
            raw.get("report_data_statement")
            or (raw.get("bindings") or {}).get("report_data_statement")
        ),
        "event_log": raw.get("cc_eventlog") or evidence.get("event_log"),
        # The backend's deployment configuration document (initdata_toml
        # inside its vm_config) — relayed verbatim so the client checks
        # sha384(initdata_toml) == tdinfo.mrconfigid (TDX) on the backend hop.
        "vm_config": evidence.get("vm_config"),
        "snp": snp,
        "signature": signature,
        # Layer-2 verification material. `signature` (Ed25519 by `tee_pubkey`)
        # is relayed verbatim and never re-signed here (we hold no backend
        # key). To be VERIFIABLE it must arrive with everything the client
        # needs to reconstruct its input and check the key: `counter` and
        # `epoch.id` complete `signature_input`; `tee_pubkey` is the Ed25519
        # verifying key (public); `keyset`/`keyset_digest` bind that key into
        # the hardware quote (report_data_statement commits keyset_digest).
        # All are PUBLIC. A MISSING/EMPTY signature (the shared cache path,
        # which binds no caller) leaves these empty — the caller then sees
        # "no caller-binding" and falls back to epoch freshness. Surface them
        # only when a real signature is present, never as counter=0 noise.
        "counter": counter if signature else None,
        "tee_pubkey": raw.get("tee_pubkey") if signature else None,
        "keyset": raw.get("keyset"),
        "keyset_digest": (raw.get("bindings") or {}).get("keyset_digest"),
        "signature_input": _LAYER2_SIGNATURE_INPUT if signature else None,
        "cert_chain": evidence.get("cert_chain"),
        "quote_sha256": hashlib.sha256(digest_src).hexdigest(),
        "api_base": api_base,
    }
    # FRESH NONCE-BOUND composite (Phase 4b): when a caller nonce was forwarded,
    # the backend mints a fresh CPU quote (REPORTDATA = nonce-derived statement)
    # AND fresh per-GPU evidence echoing the SAME nonce in each SPDM frame.
    # Surface the GPU inventory + per-leg timing so the client can see the whole
    # CPU+8-GPU mint actually happened, not just a cached epoch quote.
    if nonce:
        out["nonce_echoed"] = raw.get("nonce")
        out["fresh"] = bool(raw.get("fresh"))
        out["gpu_count"] = raw.get("gpu_count")
        out["gpu_arch"] = raw.get("gpu_arch")
        out["evidence_digest"] = raw.get("evidence_digest")
        out["gpus"] = raw.get("gpus")
        out["timing"] = dict(raw.get("timing") or {}) or None
    return out


def _prune_backend_quotes() -> None:
    """Bound the cache to registered backends (simple-shuffle has 1-2 rows)."""
    while len(_backend_quotes) > _BACKEND_QUOTE_MAX:
        _backend_quotes.pop(next(iter(_backend_quotes)))


async def _fetch_backend_evidence(
    url: str, nonce: str | None = None
) -> dict[str, Any]:
    """One evidence fetch from the backend guest over strict east-west mTLS.

    Two modes, selected by `nonce`:

    * ``nonce=None`` — the SHARED EPOCH path. Binds NO caller nonce on purpose:
      a hardware quote is sealed at mint, so a nonce in `report_data` would make
      the quote usable by exactly that nonce's owner and therefore uncachable.
      The backend's cached quote binds its **epoch statement** instead (identical
      for every caller inside the epoch) and returns the exact hashed bytes as
      `report_data_statement`, so ANY caller can verify
      `SHA-256(statement) ‖ 32 zero bytes == report_data`. Cheap and cacheable.

    * ``nonce=<64-hex>`` — the FRESH NONCE-BOUND path (Phase 4b). The backend
      mints a NEW quote with the caller nonce bound into REPORTDATA and collects
      fresh per-GPU (CPU + 8-GPU) evidence that echoes the SAME nonce in each
      SPDM GET_MEASUREMENTS frame. This is the "fresh CPU+8GPU per client nonce"
      design: one fresh composite per nonce-bearing request. Sealed to that nonce
      — deliberately UNCACHABLE (the caller below bypasses the cache for it).

    `role` selects the backend's role-scoped route.
    """
    import httpx

    material = _eastwest_client_material()
    client_kwargs: dict[str, Any] = {"timeout": 30.0}
    if material is not None:
        client_kwargs["cert"], client_kwargs["verify"] = material
    params: dict[str, str] = {"role": _BACKEND_ROLE}
    if nonce:
        params["nonce"] = nonce.lower()
    async with httpx.AsyncClient(**client_kwargs) as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return json.loads(resp.content)


async def _backend_evidence(
    api_base: str, nonce: str | None = None
) -> dict[str, Any] | None:
    """The backend's evidence.

    Two paths, selected by `nonce`:

    * ``nonce=None`` (default) — SHARED epoch quote, cached in this process for
      < TTL seconds and shared by every API key. A warm hit is a dict read.

    * ``nonce=<64-hex>`` (Phase 4b) — FRESH CPU+8GPU mint sealed to that nonce.
      Bypasses BOTH the cache read AND the cache write (a nonce-bound composite
      is uncachable by design — serving it to another caller would leak a quote
      whose REPORTDATA names a nonce that is not theirs). Each fresh result is
      fetched, normalized, fed to the breaker, and returned WITHOUT being
      stored. The shared epoch cache is left untouched (still serves the
      non-nonce path cheaply).

    Returns None when no acceptable evidence is available (fail closed to the
    boundary label).
    """
    key = _backend_attest_url(api_base)
    if nonce:
        _backend_quote_stats["fresh_nonce"] += 1
        try:
            raw = await _fetch_backend_evidence(key, nonce=nonce)
        except Exception:
            _backend_quote_stats["fetch_error"] += 1
            return None
        entry = _normalize_backend_evidence(raw, api_base, nonce=nonce)
        if entry is None:
            return None
        entry["_minted_monotonic"] = time.monotonic()
        entry["_source"] = "fresh-nonce"
        await _observe_backend_evidence(key, entry)  # fresh verify (breaker)
        return entry
    entry = _backend_quotes.get(key)
    if entry is not None and (time.monotonic() - entry["_minted_monotonic"]) < _BACKEND_QUOTE_TTL_S:
        _backend_quote_stats["hit"] += 1
        entry["_source"] = "cache"
        return entry

    lock = _backend_quote_locks.setdefault(key, asyncio.Lock())
    async with lock:
        # Double-check after acquiring: a concurrent caller may have minted.
        entry = _backend_quotes.get(key)
        if (
            entry is not None
            and (time.monotonic() - entry["_minted_monotonic"]) < _BACKEND_QUOTE_TTL_S
        ):
            _backend_quote_stats["hit"] += 1
            entry["_source"] = "cache"
            await _observe_backend_evidence(key, entry)  # cheap re-verify (breaker)
            return entry
        _backend_quote_stats["miss"] += 1
        try:
            raw = await _fetch_backend_evidence(key)
        except Exception:
            _backend_quote_stats["fetch_error"] += 1
            return None
        entry = _normalize_backend_evidence(raw, api_base)
        if entry is None:
            return None
        entry["_minted_monotonic"] = time.monotonic()
        entry["_source"] = "fetch"
        _backend_quotes[key] = entry
        _prune_backend_quotes()
        await _observe_backend_evidence(key, entry)  # fresh verify (breaker)
        return entry


# ---------------------------------------------------------------------------
# Measurement-drift circuit breaker (gateway detective + enforcement)
# ---------------------------------------------------------------------------
# A compromised / tampered backend whose measured launch inputs MOVE is caught
# here and cut off from the data plane. The design is deliberately layered so
# one detector does not mask another:
#
#   TRIP   = the backend's COMPOSITION changed -> it must not serve. Auto-block
#            its LiteLLM row (POST /model/block) + alert. Measured drift is a
#            breach signal.
#   DEGRADE= evidence is unavailable/stale (freshness gap) -> still serving,
#            but only with the boot boundary label and an explicit error
#            header. A freshness gap is an EVIDENCE gap, not proof of drift, so
#            it never blocks a serving backend (fail-closed on fabrication).
#
# Freshness naming (matches CLIENT-FACING-ATTESTATION.md "Backend evidence"):
# Layer 1 = hardware epoch (the DCAP quote, `report_data` binds the epoch
# statement); Layer 2 = per-request signature by the backend's `tee-pubkey`
# (Ed25519, distinct from its TLS key) over
# `SHA-256(quote) || SHA-256(nonce) || epoch_id || counter`, `counter` a
# monotonic per-epoch request counter. The breaker treats an expired/absent
# epoch as a DEGRADE (Layer-1 freshness gap), never a TRIP.
#
# Seven trip conditions over the normalized backend envelope. TDX registers
# are uppercase hex; trust-vector semantics follow the Trustee EAR draft-04
# AR4SI levels (APPROVED_CONFIG=2 / APPROVED_FILES=2; low = trusted).
#
# All state is IN-MEMORY and per-process. This is a detective/enforcement layer
# on top of the authoritative KBS resource-policy gate
# (nim/eastwest/resource-policy.rego `image_gen_measured`), which blocks a
# drifted guest's cert fetch at the source. It is NOT a durable store and NOT a
# source of truth across gateway restarts.
#
# Enforcement (auto-block + alert) is OPT-IN: default OFF. Enabled with
# KUBETEE_BREAKER_ENFORCE=1 once the triage/rollback runbook is in place —
# flipping a serving model to 503 must be a reviewed deployment, never an
# agent reflex (see the pre-apply/ask-before rules). Detection and the 503
# surface are always on.

# Declared reference measures for the image-gen SGLang backend class. Source:
# kubetee-subnet/docs/tee-measurements-sglang.tdx.draft.json. A field left None
# is not-yet-captured and therefore not enforced (a None expectation can never
# trip — enforced only when set).
_EXPECTED_BACKEND: dict[str, Any] = {
    "role": os.environ.get("KUBETEE_BACKEND_EXPECTED_ROLE", "image-gen"),
    "mrconfigid": os.environ.get(
        "KUBETEE_BACKEND_EXPECTED_MRCONFIGID",
        "0484a58e5927efd31bf871c74bcc9f1768f4335bb92340176989b3c5b320f934"
        "1d772b9e3e9c4fe4d824613cc19e6e0b",
    ).lower(),
    "mrtd": (os.environ.get("KUBETEE_BACKEND_EXPECTED_MRTD") or "").lower() or None,
    "rtmr0": (os.environ.get("KUBETEE_BACKEND_EXPECTED_RTMR0") or "").lower() or None,
    "rtmr1": (os.environ.get("KUBETEE_BACKEND_EXPECTED_RTMR1") or "").lower() or None,
    "rtmr2": (os.environ.get("KUBETEE_BACKEND_EXPECTED_RTMR2") or "").lower() or None,
    "rtmr3": (os.environ.get("KUBETEE_BACKEND_EXPECTED_RTMR3") or "").lower() or None,
    "ovmf_fd_sha256": (
        os.environ.get("KUBETEE_BACKEND_EXPECTED_OVMF")
        or "2a2dc2710b0cfafc813310c7e98c67b72b919b8e1572d52a4c79466a2e499226"
    ).lower() or None,
}

_BREAKER_ENFORCE: bool = os.environ.get("KUBETEE_BREAKER_ENFORCE", "0").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
_BREAKER_BACKEND: Final[str] = os.environ.get(
    "KUBETEE_BREAKER_BACKEND", "kimi-k3-1-pro39-sglang-b300-cc-0"
)
_BREAKER_BLOCK_URL: Final[str] = os.environ.get(
    "KUBETEE_BREAKER_BLOCK_URL", "https://llm.kubetee.ai/model/block"
)
_BREAKER_ALERT_URL: Final[str] = os.environ.get("KUBETEE_BREAKER_ALERT_URL", "")

# 1 = CLOSED (healthy) · 2 = OPEN (tripped; serving blocked) · 3 = HALF-OPEN.
BREAKER_CLOSED: Final[int] = 1
BREAKER_OPEN: Final[int] = 2
BREAKER_HALF_OPEN: Final[int] = 3

_HEX_RE: Final = re.compile(r"[0-9a-f]{2,}")


class _Breaker:
    """One-backend CLOSED/OPEN/HALF-OPEN state machine (in-memory)."""

    __slots__ = ("state", "trips", "degradations", "opened_at", "last_reason", "last_degrade_reason")

    def __init__(self) -> None:
        self.state: int = BREAKER_CLOSED
        self.trips: int = 0
        self.degradations: int = 0
        self.opened_at: float | None = None
        self.last_reason: str | None = None
        self.last_degrade_reason: str | None = None

    @property
    def open(self) -> bool:
        return self.state == BREAKER_OPEN


_breakers: dict[str, _Breaker] = {}
_breaker_lock = asyncio.Lock()
_breaker_notified: set[str] = set()  # one alert+block per trip; no storm
_breaker_stats: dict[str, int] = {"checked": 0, "tripped": 0, "degraded": 0, "enforce_ok": 0, "enforce_err": 0}


def _breaker_for(endpoint: str) -> _Breaker:
    return _breakers.setdefault(endpoint, _Breaker())


def _extract_registers(evidence: dict[str, Any]) -> dict[str, str | None]:
    """Pull MRTD/RTMR0-3/MRCONFIGID from the TDX quote body, hex -> lower.

    Verifies against the quote a client reads, not self-declared summary text.
    An SNP backend has no TDX registers (its composition is `measurement`/
    `host_data`), so it returns all-None here and the register trip conditions
    cannot fire for it (by design — enforce an SNP reference in the SNP twin).

    Byte offsets are the AUTHORITATIVE `TDReport10` layout (Intel TDX
    attestation; the same struct the validated `gm-miner/attestd`
    `kubetee_verify::Measurements::of` reads via `dcap_qvl::quote::TDReport10`).
    The report body starts at quote byte 48 (the quote header), and
    `TDReport10` is the base of BOTH TDX Quote v4 (TD10) and v5 (TD15) report
    bodies — the first 584 bytes (the fields below) are identical, so these
    offsets hold across versions. Field/offset table (body-relative):

        tee_tcb_svn     [  0: 16]   mr_td           [136:184]
        mr_seam         [ 16: 64]   mr_config_id    [184:232]
        mr_signer_seam  [ 64:112]   mr_owner        [232:280]
        seam_attributes [112:120]   mr_owner_config [280:328]
        td_attributes   [120:128]   rt_mr0          [328:376]
        xfam            [128:136]   rt_mr1          [376:424]
                                    rt_mr2          [424:472]
                                    rt_mr3          [472:520]
        report_data     [520:584]  (quote-absolute [568:632])

    The `report_data` cross-check (quote-absolute 568) matches
    `kubetee_binding.py`'s documented "REPORTDATA offset 568 (TDREPORT1.6
    layout)" — a wrong base/offset scheme would move every register, so this
    anchors the whole table. Registers are read as their raw hex (byte order
    as stored), matching `hex::encode` of the register bytes in `kubetee_verify`.
    """
    out: dict[str, str | None] = {"mrtd": None, "rtmr0": None, "rtmr1": None, "rtmr2": None, "rtmr3": None, "mrconfigid": None}
    if evidence.get("tee") != "tdx":
        return out
    quote = evidence.get("quote")
    if not isinstance(quote, str) or not quote:
        return out
    try:
        raw = base64.b64decode(quote + "=" * (-len(quote) % 4), validate=False)
    except Exception:
        return out
    # Prefer RELAYED parsed claims when the backend carries them (evidence.tdx
    # or evidence.claims.quote.body.*) — byte-exact from an attester/verifier.
    claims = _tdx_body_claims(evidence)
    if claims:
        for src, dst in (
            ("mr_td", "mrtd"),
            ("rtmr_0", "rtmr0"),
            ("rtmr_1", "rtmr1"),
            ("rtmr_2", "rtmr2"),
            ("rtmr_3", "rtmr3"),
            ("mr_config_id", "mrconfigid"),
        ):
            v = claims.get(src)
            if isinstance(v, str) and _HEX_RE.fullmatch(v.strip().lower()):
                out[dst] = v.strip().lower()
        return out
    # Raw-quote reconstruction: quote header is 48 bytes, then the TDReport10
    # body at the offsets above. Requires the full TDReport10 body present.
    if len(raw) < 48 + 584:
        return out
    body = raw[48:]

    def reg(a: int, b: int) -> str:
        return body[a:b].hex()

    out["mrtd"] = reg(136, 184)       # mr_td
    out["mrconfigid"] = reg(184, 232)  # mr_config_id
    out["rtmr0"] = reg(328, 376)      # rt_mr0
    out["rtmr1"] = reg(376, 424)      # rt_mr1
    out["rtmr2"] = reg(424, 472)      # rt_mr2
    out["rtmr3"] = reg(472, 520)      # rt_mr3
    return out


def _tdx_body_claims(evidence: dict[str, Any]) -> dict[str, Any]:
    """Parsed TDX quote-body claims if the evidence carries them.

    The relayed backend envelope may carry parsed claims (evidence.tdx.* or a
    claims tree) alongside the raw quote. When present they are authoritative
    (byte-exact from the attester/verifier), so prefer them over offset
    reconstruction. Returns {} when absent.
    """
    for key in ("tdx", "claims", "quote_claims"):
        node = evidence.get(key)
        if isinstance(node, dict):
            body = node.get("quote", node).get("body") if isinstance(node.get("quote", node), dict) else None
            if isinstance(body, dict) and any(k in body for k in ("mr_td", "rtmr_0", "mr_config_id")):
                return body
    return None


def _jcs(obj: Any) -> bytes:
    """RFC 8785 JCS canonical serialization (the signature preimage).

    Matches `kubetee-website/scripts/build-tee-measurements-registry.py`'s `jcs`
    so the registry Ed25519 signature (over the doc minus `signature`) verifies
    byte-for-byte. Objects serialize with sorted keys and no whitespace.
    """
    def enc(o: Any) -> str:
        if o is None:
            return "null"
        if o is True:
            return "true"
        if o is False:
            return "false"
        if isinstance(o, str):
            return json.dumps(o, ensure_ascii=False, separators=(",", ":"))
        if isinstance(o, int):
            return str(o)
        if isinstance(o, float):
            # JCS numbers: integral floats serialize like ints; else repr round-trip.
            return str(int(o)) if o.is_integer() else repr(o)
        if isinstance(o, dict):
            items = sorted(o.items(), key=lambda kv: kv[0])
            return "{" + ",".join(
                json.dumps(k, ensure_ascii=False, separators=(",", ":")) + ":" + enc(v)
                for k, v in items
            ) + "}"
        if isinstance(o, (list, tuple)):
            return "[" + ",".join(enc(v) for v in o) + "]"
        raise TypeError(f"JCS cannot serialize {type(o).__name__}")

    return enc(obj).encode("utf-8")


def _iso_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _parse_ts(value: Any) -> datetime.datetime | None:
    if not value:
        return None
    try:
        ts = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return ts if ts.tzinfo else ts.replace(tzinfo=datetime.timezone.utc)
    except Exception:
        return None


def _verify_registry_signature(registry: dict[str, Any]) -> bool:
    """True iff the registry's Ed25519 `signature` verifies against the pinned key.

    Fails closed on any structural/verification problem EXCEPT an absent pinned
    key (no key -> signature not checked, but matching still runs). Uses only
    the stdlib Ed25519 (`cryptography` is not a gateway dependency).
    """
    import base64 as _b64

    sig_block = registry.get("signature")
    if not isinstance(sig_block, dict):
        return False
    if not _REGISTRY_PUBLIC_KEY_B64:
        return True  # no pinned key: match records, skip signature check
    try:
        key_bytes = _b64.b64decode(_REGISTRY_PUBLIC_KEY_B64 + "=" * (-len(_REGISTRY_PUBLIC_KEY_B64) % 4))
        sig = _b64.b64decode(str(sig_block.get("sig", "")) + "=" * (-len(str(sig_block.get("sig", ""))) % 4))
        unsigned = {k: v for k, v in registry.items() if k != "signature"}
        preimage = _jcs(unsigned)
    except Exception:
        return False
    # stdlib Ed25519 (Python 3.8+): the public key is the raw 32 bytes or a DER
    # SPKI; here we expect the raw 32-byte public key.
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )

        pub = Ed25519PublicKey.from_public_bytes(key_bytes)
        pub.verify(sig, preimage)
        return True
    except Exception:
        return False


def _registry_records(registry: dict[str, Any]) -> list[dict[str, Any]]:
    return [r for r in (registry.get("records") or []) if isinstance(r, dict)]


def _match_registry_record(
    regs: dict[str, str | None], records: list[dict[str, Any]]
) -> tuple[bool, str | None]:
    """(approved, reason) — match live regs against ANY active (non-expired) record.

    A record matches when every field it declares is present and equal in the
    observed registers (None/absent expected fields are not enforced). A record
    outside its `valid_until` window is deprecated and skipped (the next record
    is tried), mirroring the 90-day deprecation lifecycle. Returns (True,
    record_id) on the first active match; (False, reason) when no active record
    matches.
    """
    now = _iso_now()
    active_checked = 0
    for rec in records:
        rec_id = str(rec.get("id") or rec.get("model") or "")
        status = str(rec.get("status") or "active").lower()
        if status in ("deprecated", "revoked", "retired"):
            continue
        valid_until = _parse_ts(rec.get("valid_until"))
        if valid_until is not None and valid_until <= now:
            continue  # expired/deprecated — never match
        active_checked += 1
        expected = rec.get("measurements") if isinstance(rec.get("measurements"), dict) else {}
        mismatches: list[str] = []
        compared = 0
        for name in _RECORD_FIELDS:
            exp = expected.get(name)
            if not exp:
                continue  # a None/absent expectation can never trip
            got = regs.get(name)
            compared += 1
            exp_norm = str(exp).lower().replace("hex:", "")
            if got and got != exp_norm:
                mismatches.append(f"{name}-drift: got {got[:24]} expected {exp_norm[:24]}")
            elif got is None:
                mismatches.append(f"{name}-absent: record {rec_id or '<unlabeled>'} declares it but evidence has none")
        if compared == 0:
            continue  # record declares no enforced fields — not a usable match
        if not mismatches:
            return True, rec_id or "<unlabeled>"
    if active_checked == 0:
        return False, "registry-no-active-record: every record is deprecated/expired"
    return False, (
        "registry-no-match: live TDX registers match no active record "
        f"({active_checked} active checked)"
    )


async def _load_registry(force: bool = False) -> dict[str, Any] | None:
    """Fetch + verify + cache the reference registry; None on failure.

    Caches a verified registry for < TTL. A stale cache is served on a refetch
    failure (the allowlist does not flap to deny on a transient network blip);
    an empty cache with a failed fetch returns None and the fallback below
    applies.
    """
    global _registry_cache, _registry_cache_monotonic
    if not force and _registry_cache is not None:
        if (time.monotonic() - _registry_cache_monotonic) < _REGISTRY_CACHE_TTL_S:
            return _registry_cache
    import httpx

    try:
        async with httpx.AsyncClient(timeout=_REGISTRY_TIMEOUT_S) as client:
            resp = await client.get(_REGISTRY_URL)
            resp.raise_for_status()
            registry = json.loads(resp.content)
    except Exception:
        return _registry_cache  # stale-ok; None if never loaded
    if not isinstance(registry, dict) or not _verify_registry_signature(registry):
        return _registry_cache  # reject tampered/unsigned doc; keep last good
    _registry_cache = registry
    _registry_cache_monotonic = time.monotonic()
    return registry


def _verify_backend_evidence(
    evidence: dict[str, Any], registry: dict[str, Any] | None = None
) -> tuple[list[str], list[str]]:
    """(trip_conditions, freshness_gaps) for one normalized backend envelope.

    `registry` is a pre-fetched verified reference registry (the async caller
    loads it). When None, the in-process cache is used (may be None — e.g. the
    sync unit tests, where the env `_EXPECTED_BACKEND` fallback applies).

    Returns the list of METADATA/drift trip conditions (measurement drift —
    safe to trip on) and the list of FRESHNESS gaps (degrade, never trip).
    """
    trips: list[str] = []
    gaps: list[str] = []

    # (1) and (2) — the two hard composition gates, role + pinned InitData.
    role = str(evidence.get("role") or "")
    if _EXPECTED_BACKEND["role"] and role != _EXPECTED_BACKEND["role"]:
        trips.append(f"role-mismatch: got {role!r} expected {_EXPECTED_BACKEND['role']!r}")
    regs = _extract_registers(evidence)
    exp = _EXPECTED_BACKEND["mrconfigid"]
    if exp and regs.get("mrconfigid") and regs["mrconfigid"] != exp:
        trips.append(f"mrconfigid-drift: got {regs['mrconfigid'][:24]} expected {exp[:24]}")
    elif exp and evidence.get("tee") == "tdx" and not regs.get("mrconfigid"):
        # TDX evidence that hides its registers is itself suspicious: a
        # verifier cannot confirm composition, so treat absence as a trip
        # rather than silently trusting an opaque guest.
        trips.append("mrconfigid-absent: TDX evidence carries no readable MRCONFIGID")

    # (3..7) — the five TDX launch registers + OVMF. Primary gate is the SIGNED
    # reference REGISTRY (any-active-record match); the env `_EXPECTED_BACKEND`
    # per-field pins are the FALLBACK when no registry is reachable. A registry
    # match that approves the whole record replaces the per-field trips — that
    # is the `policy.match = any-active-record` contract. Enforced ONLY when a
    # reference is captured (None = not captured = cannot trip).
    reg_trip_names = ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3")
    registry = registry if registry is not None else _registry_cache
    records = _registry_records(registry) if registry else []
    if records:
        approved, match_reason = _match_registry_record(regs, records)
        if not approved:
            trips.append(match_reason)  # no active record matches -> drift
    else:
        for name in reg_trip_names:
            expected = _EXPECTED_BACKEND.get(name)
            got = regs.get(name)
            if expected and got and got != expected:
                trips.append(f"{name}-drift: got {got[:24]} expected {expected[:24]}")
    ovmf_exp = _EXPECTED_BACKEND.get("ovmf_fd_sha256")
    ovmf_got = str(evidence.get("ovmf_fd_sha256") or evidence.get("ovmf_sha256") or "").strip().lower()
    if ovmf_exp and ovmf_got and ovmf_got != ovmf_exp:
        trips.append(f"ovmf-drift: got {ovmf_got[:24]} expected {ovmf_exp[:24]}")

    # Freshness — never a trip. An expired or unset epoch bounds freshness; a
    # gap means "cannot prove recent", not "composition changed".
    epoch = evidence.get("epoch") or {}
    if not epoch.get("id"):
        gaps.append("epoch-absent: no epoch_id in evidence")
    valid_until = epoch.get("valid_until")
    if valid_until:
        import datetime

        try:
            expires = datetime.datetime.fromisoformat(str(valid_until).replace("Z", "+00:00"))
            if expires <= datetime.datetime.now(datetime.timezone.utc):
                gaps.append(f"epoch-expired: valid_until {valid_until} is past")
        except Exception:
            gaps.append(f"epoch-expiry-unparseable: {valid_until!r}")
    if not evidence.get("quote") and not evidence.get("snp"):
        gaps.append("hardware-evidence-absent: no quote and no snp report")
    return trips, gaps


async def _post_block_and_alert(reason: str) -> None:
    """Auto-block the row + alert on a trip (opt-in via KUBETEE_BREAKER_ENFORCE)."""
    import httpx

    body = {"model_name": _BREAKER_BACKEND}
    headers = {"Content-Type": "application/json"}
    master = os.environ.get("LITELLM_MASTER_KEY") or os.environ.get("KUBETEE_MASTER_KEY")
    if master:
        headers["Authorization"] = f"Bearer {master}"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(_BREAKER_BLOCK_URL, json=body, headers=headers)
            ok = resp.status_code < 300
            _breaker_stats["enforce_ok" if ok else "enforce_err"] += 1
    except Exception:
        _breaker_stats["enforce_err"] += 1
        ok = False
    if _BREAKER_ALERT_URL:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(
                    _BREAKER_ALERT_URL,
                    json={
                        "event": "kubetee-measurement-drift-breaker-trip",
                        "backend": _BREAKER_BACKEND,
                        "reason": reason,
                        "action": "model/block",
                        "succeeded": ok,
                    },
                )
        except Exception:
            _breaker_stats["enforce_err"] += 1


async def _trip_breaker(endpoint: str, evidence: dict[str, Any], trips: list[str]) -> None:
    """Open the breaker on measurement drift and (if enforcing) block + alert."""
    breaker = _breaker_for(endpoint)
    reason = "; ".join(trips)
    breaker.state = BREAKER_OPEN
    breaker.opened_at = time.monotonic()
    breaker.trips += 1
    breaker.last_reason = reason
    _breaker_stats["tripped"] += 1
    key = f"{endpoint}|{reason}"
    if key in _breaker_notified:
        return  # one notification per distinct trip; no alert storm
    _breaker_notified.add(key)
    if _BREAKER_ENFORCE:
        await _post_block_and_alert(reason)


async def _observe_backend_evidence(endpoint: str, evidence: dict[str, Any] | None) -> None:
    """Run the verifier on a fetched/relayed envelope and drive the breaker.

    Called on every backend-evidence fetch (cold cache). A warm cache hit
    re-verifies cheaply via `breaker_guard`. Measurement drift trips; a
    freshness gap degrades only.
    """
    async with _breaker_lock:
        _breaker_stats["checked"] += 1
        breaker = _breaker_for(endpoint)
        if breaker.open:
            return  # already tripped; stay open until half-open success
        if evidence is None:
            return  # handled as a freshness gap upstream (label + error header)
        registry = await _load_registry()
        trips, gaps = _verify_backend_evidence(evidence, registry=registry)
        if trips:
            await _trip_breaker(endpoint, evidence, trips)
            return
        if gaps:
            breaker.degradations += 1
            breaker.last_degrade_reason = "; ".join(gaps)
            _breaker_stats["degraded"] += 1


def breaker_state(endpoint: str | None) -> dict[str, Any]:
    """Introspection for tests and a future status surface (read-only)."""
    ep = endpoint or _BREAKER_BACKEND
    breaker = _breakers.get(ep, _Breaker())
    return {
        "backend": ep,
        "state": {BREAKER_CLOSED: "CLOSED", BREAKER_OPEN: "OPEN", BREAKER_HALF_OPEN: "HALF-OPEN"}[breaker.state],
        "open": breaker.open,
        "trips": breaker.trips,
        "degradations": breaker.degradations,
        "last_reason": breaker.last_reason,
        "last_degrade_reason": breaker.last_degrade_reason,
        "enforce": _BREAKER_ENFORCE,
        "expected": {k: (v[:16] + "…" if isinstance(v, str) and len(v) > 16 else v) for k, v in _EXPECTED_BACKEND.items()},
    }


def breaker_guard(endpoint: str) -> dict[str, str] | None:
    """Response headers to inject when the breaker blocks/degrades this backend.

    Returns None when healthy. On an OPEN (measurement-drift) breaker returns
    headers that map to an HTTP 503 auto-block (the caller surfaces them and
    stops routing to this backend). A freshness gap returns error-tag headers
    WITHOUT blocking (degraded-not-tripped).
    """
    breaker = _breakers.get(endpoint)
    if breaker is None:
        return None
    if breaker.open:
        return {
            "X-KubeTEE-Breaker-State": "OPEN",
            "X-KubeTEE-Breaker-Trip": breaker.last_reason or "measurement drift",
            "X-KubeTEE-Breaker-Action": "auto-block (HTTP 503)",
        }
    if breaker.last_degrade_reason:
        return {
            "X-KubeTEE-Breaker-State": "DEGRADED",
            "X-KubeTEE-Breaker-Reason": breaker.last_degrade_reason,
        }
    return None


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


# ---------------------------------------------------------------------------
# SNP raw-report serialization (AMD ATT_REP_FW_LEN = 1184 bytes)
# ---------------------------------------------------------------------------
# Reconstructs the exact binary AMD SEV-SNP attestation report from CoCo's
# structured JSON so an offline verifier (SayGM/Chutes/gm-miner) can check the
# VCEK ECDSA P-384/SHA-384 signature over `raw_report[..0x2a0]` WITHOUT
# hand-assembling the layout. This is a faithful port of `virtee/sev` 9.0.0
# `AttestationReport`'s `Encoder` (validated byte-for-byte against the
# `sev`-oracle golden vector in the reference verifier's `snp-report-bytes`).
#
# Two non-obvious wire details (the reason a hand-rolled encoder breaks):
#   * `Version` (current/committed) is a 24-bit LITTLE-ENDIAN int encoded as
#     [build, minor, major] — NOT [major, minor, build].
#   * `signature` is a 144-byte block = r(72) || s(72) at offset 0x2A0.
# The report version selects the reserved/mitigation-vector span; only
# (V6, Venice) carries extended TCBs. Our Milan/Genoa/Turin V3/V5 guests leave
# the ETCB span MBZ.
_SNP_REPORT_LEN: Final = 1184
_SNP_SIGNED_BODY_LEN: Final = 0x2A0


def _snp_cpu_generation(report: dict[str, Any]) -> str:
    """Map cpuid family/model to the TCB byte layout, per sev::Generation."""
    fam = report.get("cpuid_fam_id") or 0
    model = report.get("cpuid_mod_id") or 0
    if fam == 0x19 and model <= 0x0F:
        return "milan"
    if fam == 0x19 and ((0x10 <= model <= 0x1F) or (0xA0 <= model <= 0xAF)):
        return "genoa"
    if fam == 0x1A and 0x00 <= model <= 0x1F:
        return "turin"
    if fam == 0x1A and ((0x50 <= model <= 0x5F) or (0xC0 <= model <= 0xCF)):
        return "venice"
    raise EvidenceError(f"SNP unknown CPU family/model 0x{fam:x}/0x{model:x}")


def _snp_tcb_bytes(tcb: dict[str, Any], gen: str) -> bytes:
    """Serialize an 8-byte TCB in the generation's wire order (sev TcbVersion)."""
    fmc = (tcb.get("fmc") or 0) & 0xFF
    bootloader = (tcb.get("bootloader") or 0) & 0xFF
    tee = (tcb.get("tee") or 0) & 0xFF
    snp = (tcb.get("snp") or 0) & 0xFF
    ucode = (tcb.get("microcode") or 0) & 0xFF
    if gen in ("milan", "genoa"):
        return bytes([bootloader, tee, 0, 0, 0, 0, snp, ucode])
    if gen == "turin":
        return bytes([fmc, bootloader, tee, snp, 0, 0, 0, ucode])
    # Venice: fmc, tee, snp; no bootloader/microcode.
    return bytes([fmc, tee, snp, 0, 0, 0, 0, 0])


def _snp_version_bytes(version: dict[str, Any]) -> bytes:
    """sev encodes Version as [build, minor, major] (24-bit little-endian)."""
    return bytes([
        (version.get("build") or 0) & 0xFF,
        (version.get("minor") or 0) & 0xFF,
        (version.get("major") or 0) & 0xFF,
    ])


def _snp_raw_report(report: dict[str, Any]) -> bytes:
    """Serialize the structured report to the exact 1184-byte AMD binary.

    Fails closed on any field-shape error (via _snp_bytes) or unknown CPU.
    """
    ab = lambda name: _snp_bytes(report.get(name), name)  # noqa: E731
    version = report.get("version", 3)
    if isinstance(version, bool) or not isinstance(version, int):
        raise EvidenceError(f"unsupported SNP report version: {version!r}")
    variant = "V2" if version == 2 else ("V3" if version in (3, 4) else ("V5" if version == 5 else "V6"))
    gen = _snp_cpu_generation(report)

    out = bytearray()
    out += int(version).to_bytes(4, "little")
    out += (report.get("guest_svn") or 0).to_bytes(4, "little")
    out += (report.get("policy") or 0).to_bytes(8, "little")
    out += ab("family_id") + ab("image_id")
    out += (report.get("vmpl") or 0).to_bytes(4, "little")
    out += (report.get("sig_algo") or 0).to_bytes(4, "little")
    out += _snp_tcb_bytes(report.get("current_tcb") or {}, gen)
    out += (report.get("plat_info") or 0).to_bytes(8, "little")
    out += (report.get("key_info") or 0).to_bytes(4, "little")
    out += bytes(4)  # reserved
    out += ab("report_data") + ab("measurement") + ab("host_data")
    out += ab("id_key_digest") + ab("author_key_digest")
    out += ab("report_id") + ab("report_id_ma")
    out += _snp_tcb_bytes(report.get("reported_tcb") or {}, gen)

    if variant == "V2":
        out += bytes(24) + ab("chip_id")
    else:
        out += bytes([
            (report.get("cpuid_fam_id") or 0) & 0xFF,
            (report.get("cpuid_mod_id") or 0) & 0xFF,
            (report.get("cpuid_step") or 0) & 0xFF,
        ])
        out += bytes(21) + ab("chip_id")

    out += _snp_tcb_bytes(report.get("committed_tcb") or {}, gen)
    out += _snp_version_bytes(report.get("current") or {})
    out += bytes(1)  # reserved
    out += _snp_version_bytes(report.get("committed") or {})
    out += bytes(1)  # reserved
    out += _snp_tcb_bytes(report.get("launch_tcb") or {}, gen)

    if variant in ("V2", "V3"):
        out += bytes(40)  # reserved (no mitigation vectors pre-V5)
    else:
        out += (report.get("launch_mit_vector") or 0).to_bytes(8, "little")
        out += (report.get("current_mit_vector") or 0).to_bytes(8, "little")
        out += bytes(24)

    # Extended TCBs are (V6, Venice) only; the 96-byte span is MBZ elsewhere.
    out += bytes(96)
    out += bytes(32)  # reserved before the signature block

    # The signature block is 512 bytes at 0x2A0..0x4A0 (sev Signature): r(72)
    # || s(72) || 368 reserved zero bytes. The signed body is 0x2A0 (672) bytes.
    sig = report.get("signature") or {}
    out += _snp_bytes(sig.get("r"), "signature.r", 72)
    out += _snp_bytes(sig.get("s"), "signature.s", 72)
    out += bytes(_SNP_REPORT_LEN - _SNP_SIGNED_BODY_LEN - 144)

    if len(out) != _SNP_REPORT_LEN:
        raise EvidenceError(f"SNP raw report serialization is {len(out)} bytes, expected {_SNP_REPORT_LEN}")
    return bytes(out)


# AMD KDS certificate delivery (VCEK + ASK/ARK). CoCo's AA returns an EMPTY
# cert chain on our guests (the firmware cert page is empty and the guest does
# no KDS fetch), so we fetch VCEK/ASK/ARK here to complete the chain. See the
# rationale comment in `_snp_cert_chain_augment`. Caches: CA chain per product;
# VCEK per (chip, reported TCB).
_KDS_CHAIN_CACHE: dict[str, list[dict[str, Any]]] = {}
_KDS_VCEK_CACHE: dict[str, list[dict[str, Any]]] = {}
_KDS_CHAIN_URL = "https://kdsintf.amd.com/vcek/v1/{product}/cert_chain"
_KDS_VCEK_URL = "https://kdsintf.amd.com/vcek/v1/{product}/{chip_id}"
_KDS_TIMEOUT_S = 4.0
_KDS_USER_AGENT = "kubetee-litellm-attestation/1.0"
_KDS_PRODUCT = {
    "milan": "Milan", "genoa": "Genoa", "turin": "Turin", "venice": "Venice",
}


def _kds_get(url: str) -> bytes:
    """GET a resource from AMD KDS; raises on any failure (fail-safe)."""
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": _KDS_USER_AGENT})
    with urllib.request.urlopen(req, timeout=_KDS_TIMEOUT_S) as resp:
        return resp.read()


def _pem_cert_ders(pem: str) -> list[bytes]:
    """Split a PEM bundle into DER certificate blobs (in file order)."""
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", pem, re.S
    )
    return [base64.b64decode("".join(b.split())) for b in blocks]


def _cert_ders(blob: bytes) -> list[bytes]:
    """Parse an AMD KDS cert response that may be PEM **or** raw DER.

    AMD's `/cert_chain` returns a PEM bundle (ASK + ARK), but the VCEK
    endpoint returns the certificate as **raw DER** (0x30 0x82 ...) — not PEM.
    Decoding a DER body as ASCII raises and silently returned an empty chain.
    Handle both: PEM text splits into N certs; binary DER is one certificate.
    """
    if b"-----BEGIN CERTIFICATE-----" in blob:
        return _pem_cert_ders(blob.decode("ascii", errors="strict"))
    if blob and blob[0] == 0x30:  # ASN.1 SEQUENCE: a single DER certificate
        return [blob]
    return []


def _snp_cert_chain_augment(report: dict[str, Any], chain: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Complete the SNP chain to leaf-to-root VCEK -> ASK -> ARK via AMD KDS.

    CoCo's AA returns an EMPTY cert chain on our guests (the firmware cert page
    is empty at boot and the guest does no KDS fetch), so a verifier gets no
    key to check the report signature. We fetch the exact signing VCEK (for
    this report's chip + reported TCB) and the (static, per-product) ASK/ARK
    from AMD KDS and return leaf-to-root VCEK -> ASK -> ARK. This is safe to
    fetch over a network because the certs are SELF-AUTHENTICATING: the VCEK's
    signature over raw_report proves it is the real signing key, and ASK/ARK
    chain to AMD's well-known root. An untrusted KDS cannot forge evidence —
    only withhold it. On any failure we return the original chain UNCHANGED
    (never a bare ASK/ARK with no VCEK anchor, never an invented cert): the
    envelope then still carries `raw_report`, so a verifier that has AMD trust
    can fetch the certs itself. Fetches are best-effort and cached.
    """
    existing_types = {
        (e.get("cert_type") or "").upper()
        for e in chain
        if isinstance(e, dict)
    }
    have_vcek = "VCEK" in existing_types
    if have_vcek and {"ARK", "ASK"} <= existing_types:
        return chain  # already complete (VCEK + ASK + ARK)
    try:
        product = _KDS_PRODUCT[_snp_cpu_generation(report)]
    except EvidenceError:
        return chain  # unknown CPU: cannot name the KDS product (fail-safe)

    # (ASK, ARK): static per product, cached. Leaf-to-root when appended.
    ca = _KDS_CHAIN_CACHE.get(product)
    if ca is None:
        try:
            ders = _cert_ders(_kds_get(_KDS_CHAIN_URL.format(product=product)))
        except Exception:
            return chain  # KDS unreachable: keep CoCo's chain as-is (fail-safe)
        # KDS order is [ASK, ARK] (the self-signed root is last).
        labels = (["ASK", "ARK"] if len(ders) == 2 else [f"CERT{i}" for i in range(len(ders))])
        ca = [{"cert_type": lab, "data": list(der)} for lab, der in zip(labels, ders)]
        _KDS_CHAIN_CACHE[product] = ca

    if have_vcek:
        # CoCo supplied the VCEK: append only the CA certs it did not send.
        return list(chain) + [e for e in ca if (e.get("cert_type") or "").upper() not in existing_types]

    # VCEK absent (the common case on our guests): fetch the exact signing key
    # for THIS report's chip + reported TCB. The VCEK is "not necessarily the
    # newest" - it is bound to the reported_tcb, i.e. the key that actually
    # signed this report. Any failure returns the chain unchanged (fail-safe).
    try:
        chip_id = _snp_bytes(report.get("chip_id"), "chip_id", 64).hex()
        tcb = report.get("reported_tcb") or {}
        qs = urlencode({
            "blSPL": int(tcb.get("bootloader") or 0),
            "teeSPL": int(tcb.get("tee") or 0),
            "snpSPL": int(tcb.get("snp") or 0),
            "ucodeSPL": int(tcb.get("microcode") or 0),
        })
        key = f"{product}|{chip_id}|{qs}"
        vceks = _KDS_VCEK_CACHE.get(key)
        if vceks is None:
            ders = _cert_ders(
                _kds_get(_KDS_VCEK_URL.format(product=product, chip_id=chip_id) + "?" + qs)
            )
            if not ders:
                return chain
            vceks = [{"cert_type": "VCEK", "data": list(ders[0])}]
            _KDS_VCEK_CACHE[key] = vceks
    except Exception:
        return chain  # VCEK fetch failed: do NOT emit ASK/ARK with no anchor

    return vceks + ca


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
    # Reconstruct the exact 1184-byte AMD report so an offline verifier can
    # check the VCEK signature without hand-assembling the layout (the known
    # to_bytes footgun). Fails closed on any shape error above.
    raw_report = _snp_raw_report(report)
    # Complete the chain with AMD's ARK/ASK when CoCo returned only the VCEK,
    # so the verifier can anchor to AMD's root of trust without its own KDS
    # query. Best-effort + cached; on failure the chain is returned unchanged.
    full_chain = _snp_cert_chain_augment(report, cert_chain)
    # This is the protocol discriminator consumed by gm-miner, not a claim of
    # AMD trust. The latter is established only by VCEK/report verification.
    return {
        "schema": "kubetee.snp-evidence/1",
        "attestation_report": report,
        "raw_report": base64.b64encode(raw_report).decode("ascii"),
        "raw_report_len": _SNP_REPORT_LEN,
        "raw_report_sha256": hashlib.sha256(raw_report).hexdigest(),
        "cert_chain": full_chain,
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


def _latin1_headers(headers: dict[str, str]) -> dict[str, str]:
    """Coerce every header VALUE to a latin-1-safe string.

    HTTP header values are latin-1 (PEP 3333 / ASGI): a non-latin-1 byte in
    any value raises UnicodeEncodeError while the response headers freeze and
    turns a healthy completion into a 500. Attestation values can carry
    free-form backend strings (labels, reasons, names), so sanitize at this
    single choke point — the response-headers hook — rather than trusting every
    literal. ASCII is preserved verbatim; any byte that cannot encode as
    latin-1 is replaced with '?'. This is a crash guard, NOT an evidence
    decision: it never alters a digest, quote, signature, or nonce (those are
    already hex/base64 ASCII).
    """
    safe: dict[str, str] = {}
    for key, value in headers.items():
        text = value if isinstance(value, str) else str(value)
        try:
            text.encode("latin-1")
        except UnicodeEncodeError:
            text = text.encode("latin-1", "replace").decode("latin-1")
        safe[str(key)] = text
    return safe


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


def _served_keyset_digest() -> str | None:
    """The served keyset digest (commits the gateway signing key), or None."""
    try:
        with open(_TLS_CERT_PATH, "rb") as f:
            cert_pem = f.read()
        keyset = kubetee_binding.keyset_from_cert_pem(cert_pem, _TLS_DOMAIN)
        return kubetee_binding.keyset_digest(keyset)
    except Exception:
        return None


def _request_header(headers: Any, name: str) -> str | None:
    """Case-insensitive header lookup across the shapes LiteLLM passes."""
    if not headers:
        return None
    if isinstance(headers, dict):
        for k, v in headers.items():
            if str(k).lower() == name.lower():
                return v if isinstance(v, str) else str(v)
    return None


def _pre_call_request_headers(data: dict) -> dict:
    """The caller's HTTP headers from the pre-call `data` dict (best-effort).

    LiteLLM lands raw request headers in `data["proxy_server_request"]["headers"]`
    and, on some paths, mirrors them into `data["headers"]` / `data["metadata"]["headers"]`.
    Probe all three; the response hook receives `request_headers` directly.
    """
    for holder in (
        (data.get("proxy_server_request") or {}).get("headers"),
        data.get("headers"),
        (data.get("metadata") or {}).get("headers"),
    ):
        if isinstance(holder, dict) and holder:
            return holder
    return {}


async def _proof_headers(
    backend_headers: dict[str, str],
    data: dict,
    request_headers: dict[str, str],
    response: Any,
) -> dict[str, str]:
    """Proof-of-inference on the ROUTED backend pod (X-KubeTEE-Proof).

    `backend_headers` is the relayed identity set already built for this
    response (fetched ONCE upstream and shared) — its
    `X-KubeTEE-Backend-Evidence-Digest` is exactly what the proof commits to.
    Returns a gateway signature binding the routed pod's evidence to THIS
    response and the caller's anchor. Cheap + unlimited (the fresh silicon mint
    stays on the rate-limited X-KubeTEE-Nonce path).
    """
    out: dict[str, str] = {}

    # Bind the response when its body is available (non-streaming); on the
    # streaming path the body is not assembled at header-freeze -> fall back to
    # request-binding and SAY SO (mode: request-bound).
    is_stream = bool((data or {}).get("stream"))
    content, model = kubetee_proof.extract_response_content(response)
    req_digest = kubetee_proof.request_digest((data or {}).get("messages"), (data or {}).get("model"))
    if not is_stream and content:
        mode = kubetee_proof.MODE_RESPONSE_BOUND
        r_input = kubetee_proof.RECIPE_RESPONSE
        r_digest = kubetee_proof.response_digest(content, model)
    else:
        mode = kubetee_proof.MODE_REQUEST_BOUND
        r_input = kubetee_proof.RECIPE_REQUEST
        r_digest = req_digest

    # The caller's anchor: X-KubeTEE-Proof: <64hex> binds their nonce (strongest);
    # X-KubeTEE-Proof: 1 binds a request-digest anchor instead.
    anchor_val = (_request_header(request_headers, _PROOF_HEADER) or "").strip()
    if _NONCE_RE.match(anchor_val):
        anchor = {"kind": "nonce", "value": anchor_val.lower()}
    else:
        anchor = {"kind": "request-digest", "value": req_digest}

    evidence_digest = backend_headers.get("X-KubeTEE-Backend-Evidence-Digest", "")
    endpoint = backend_headers.get("X-KubeTEE-Backend-Endpoint", "")
    keyset_digest = _served_keyset_digest() or ""
    issued_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    out.update(
        kubetee_proof.proof_headers(
            response_mode=mode,
            response_input=r_input,
            response_digest_value=r_digest,
            request_anchor=anchor,
            backend_evidence_digest=evidence_digest,
            backend_endpoint=endpoint,
            keyset_digest=keyset_digest,
            issued_at=issued_at,
            signing_key=_load_serving_key(),
        )
    )
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
                "event_log": payload["cc_eventlog"],
                # vm_config carries initdata_toml (the deployment configuration
                # document, verbatim) so the client recomputes
                # sha384(initdata_toml) == host_data/MRCONFIGID from the served
                # bytes — never trust the served digest alone.
                "vm_config": kubetee_ear.vm_config(),
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



async def _backend_identity_headers(
    data: dict, litellm_call_info: dict | None, nonce: str | None = None
) -> dict[str, str]:
    """Best-effort backend identity headers for inline evidence.

    The backend's hardware evidence is fetched by `_backend_evidence`. Two modes:

    * ``nonce=None`` (default) — SHARED per-backend epoch cache: one quote per
      backend, reused for every key and every request inside its epoch. Never
      fetched per key (the `user_api_key_dict` argument is deliberately absent
      from this call: key material has no role here).
    * ``nonce=<64-hex>`` (Phase 4b) — a FRESH CPU+8GPU mint sealed to the caller
      nonce (REPORTDATA = nonce-derived statement; every GPU's SPDM frame echoes
      the same nonce). One fresh composite per nonce-bearing request, uncached.

    A warm cache hit (or a fresh mint) emits the relayed quote evidence. A
    cold/expired fetch failure falls back to the boot-time boundary label and
    says so — never a silent downgrade from a quote to a label.
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

    evidence: dict[str, Any] | None = None
    if api_base:
        evidence = await _backend_evidence(str(api_base), nonce=nonce)
        # Circuit-breaker surface (measurement drift / freshness gap). A drifted
        # (composition-changed) backend emits the OPEN -> auto-block/503 labels;
        # a freshness gap emits DEGRADED. Both are merged into the response
        # headers so the CLIENT can see why it is being cut off or degraded.
        guard = breaker_guard(_backend_attest_url(str(api_base)))
        if guard:
            headers.update(guard)

    if evidence is None:
        headers["X-KubeTEE-Backend-Attested"] = (
            "boot-time (Trustee EAR; east-west mTLS)"
        )
        if api_base:
            # ASCII only — HTTP header values are latin-1; a non-latin-1 byte
            # (the former U+2014 em-dash at byte 29) raised UnicodeEncodeError
            # and 500'd the completion the moment the graceful fallback ran
            # (cold evidence-cache miss). Keep every header value ASCII.
            headers["X-KubeTEE-Backend-Evidence-Error"] = (
                "backend evidence unavailable - boundary label only"
            )
            # A freshness gap degrades but never trips — record + surface it.
            await _observe_backend_evidence(_backend_attest_url(str(api_base)), None)
            guard = breaker_guard(_backend_attest_url(str(api_base)))
            if guard:
                headers.update(guard)
        return headers

    # Reflect what was actually minted: a fresh nonce-bound CPU+8GPU composite
    # (Phase 4b) or the shared epoch quote. Never claim freshness we don't have.
    _src = str(evidence.get("_source", "cache"))
    if nonce and _src == "fresh-nonce":
        headers["X-KubeTEE-Backend-Attested"] = "hardware-evidence (fresh cpu+gpu, nonce-bound)"
    else:
        headers["X-KubeTEE-Backend-Attested"] = "hardware-evidence (shared epoch cache)"
    epoch = evidence.get("epoch") or {}

    # Self-describing discriminators, FLAT so a client can filter without
    # decoding the envelope: WHOSE evidence (subject), WHAT it is (schema),
    # and the TEE (tee). The NIM may be TDX or SNP; the client reads `tee` —
    # it never has to know it in advance, ask for it, or pick a header name.
    headers["X-KubeTEE-Backend-Evidence-Subject"] = str(
        evidence.get("subject") or "nim-terminator"
    )
    headers["X-KubeTEE-Backend-Evidence-Schema"] = str(evidence.get("schema") or "")
    headers["X-KubeTEE-Backend-Evidence-Tee"] = str(evidence.get("tee") or "")
    if evidence.get("runtime_class"):
        headers["X-KubeTEE-Backend-Evidence-Runtime-Class"] = str(evidence["runtime_class"])
    headers["X-KubeTEE-Backend-Evidence-Digest"] = evidence["quote_sha256"]
    headers["X-KubeTEE-Backend-Evidence-Source"] = str(evidence.get("_source", "cache"))
    if epoch.get("id"):
        headers["X-KubeTEE-Backend-Epoch"] = str(epoch["id"])
    if epoch.get("issued_at"):
        headers["X-KubeTEE-Backend-Epoch-Issued-At"] = str(epoch["issued_at"])
    if epoch.get("valid_until"):
        headers["X-KubeTEE-Backend-Epoch-Valid-Until"] = str(epoch["valid_until"])
    if evidence.get("signature"):
        headers["X-KubeTEE-Backend-Evidence-Signature"] = str(evidence["signature"])
        # Flat, filterable discriminator: whether the relayed envelope carries a
        # per-request caller-binding signature (Layer 2) or is epoch-freshness
        # only (Layer 1). The plain cache path returns no signature; a
        # nonce-bound mint does. The client reads this without decoding the
        # envelope to know whether caller-binding is even present to verify.
        headers["X-KubeTEE-Backend-Evidence-Layer2"] = "present"
    else:
        headers["X-KubeTEE-Backend-Evidence-Layer2"] = "absent"

    # FRESH NONCE-BOUND telemetry (Phase 4b): the GPU inventory + the per-leg
    # timing the backend measured while minting the CPU quote and collecting the
    # GPU evidence. Only present on the fresh path. These are the observables
    # the cache/rate-limit decision is made from (how much latency a fresh
    # CPU+8-GPU mint costs per nonce-bearing request).
    if nonce and _src == "fresh-nonce":
        headers["X-KubeTEE-Backend-GPU-Count"] = str(evidence.get("gpu_count") or 0)
        if evidence.get("gpu_arch"):
            headers["X-KubeTEE-Backend-GPU-Arch"] = str(evidence["gpu_arch"])
        timing = evidence.get("timing") or {}
        if timing.get("cpu_mint_ms") is not None:
            headers["X-KubeTEE-Backend-CPU-Mint-Ms"] = str(timing["cpu_mint_ms"])
        if timing.get("gpu_collect_ms") is not None:
            headers["X-KubeTEE-Backend-GPU-Collect-Ms"] = str(timing["gpu_collect_ms"])
        if timing.get("total_ms") is not None:
            headers["X-KubeTEE-Backend-Mint-Total-Ms"] = str(timing["total_ms"])

    # ONE self-describing envelope carries the TEE-specific payload (quote +
    # event_log + report_data for TDX; native `snp` for SNP) plus cert_chain.
    # The client decodes one blob and branches on its `schema`/`tee` fields —
    # never on a header name. Inline only while it fits the header budget;
    # past that the client fetches the backend's standalone bundle.
    envelope: dict[str, Any] = {
        "subject": evidence.get("subject", "nim-terminator"),
        "schema": evidence.get("schema"),
        "tee": evidence.get("tee"),
        "role": evidence.get("role"),
        "runtime_class": evidence.get("runtime_class"),
        "epoch": epoch,
        "digest": evidence.get("quote_sha256"),
        "report_data": evidence.get("report_data"),
        "report_data_statement": evidence.get("report_data_statement"),
        "cert_chain": evidence.get("cert_chain"),
        "signature": evidence.get("signature"),
        # Layer-2 caller-binding verification material (public). `signature`
        # is Ed25519 over `signature_input` by `tee_pubkey`; `counter` +
        # `epoch.id` reconstruct the input and `keyset_digest` (committed in
        # report_data_statement) binds `tee_pubkey` into the hardware quote.
        # Without these a client cannot verify `signature` — so they ride with
        # it. Empty when the relay path returned no signature (no caller-binding).
        "counter": evidence.get("counter"),
        "tee_pubkey": evidence.get("tee_pubkey"),
        "keyset": evidence.get("keyset"),
        "keyset_digest": evidence.get("keyset_digest"),
        "signature_input": evidence.get("signature_input"),
    }
    if evidence.get("tee") == "tdx":
        envelope["quote"] = evidence.get("quote")
        envelope["event_log"] = evidence.get("event_log")
    else:
        envelope["snp"] = evidence.get("snp")
    # FRESH NONCE-BOUND (Phase 4b): a compact GPU summary + the composite digest
    # (a commitment to the FULL CPU+8GPU bundle) ride inline. The 8 raw SPDM
    # reports + cert chains are ~190 KB and would blow any HTTP header budget,
    # so they stay in the backend's standalone bundle — the client fetches
    # `/kubetee/evidence?nonce=<theirs>` for the full proofs and checks them
    # against `evidence_digest`. Inline here is what proves THIS nonce got a
    # fresh CPU+8GPU mint (not a shared epoch quote) and what the timing cost.
    if nonce and _src == "fresh-nonce":
        gpu = {
            "count": evidence.get("gpu_count"),
            "arch": evidence.get("gpu_arch"),
            "evidence_digest": evidence.get("evidence_digest"),
            "timing": evidence.get("timing"),
        }
        if evidence.get("nonce_echoed"):
            gpu["nonce_echoed"] = evidence.get("nonce_echoed")
        envelope["gpu"] = gpu
    encoded = base64.urlsafe_b64encode(
        json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).decode("ascii").rstrip("=")
    if len(encoded) <= _BACKEND_EVIDENCE_MAX_HEADER_CHARS:
        headers["X-KubeTEE-Backend-Evidence"] = encoded
    else:
        headers["X-KubeTEE-Backend-Evidence-Location"] = _backend_attest_url(str(api_base))
        headers["X-KubeTEE-Backend-Evidence-Reason"] = (
            f"evidence envelope {len(encoded)} chars exceeds inline budget "
            f"{_BACKEND_EVIDENCE_MAX_HEADER_CHARS}; fetch the standalone bundle"
        )
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

    async def async_pre_call_hook(
        self,
        user_api_key_dict: Any,
        cache: Any,
        data: dict,
        call_type: str,
    ) -> Any:
        """Rate-limit the FRESH silicon mint path (X-KubeTEE-Nonce).

        One fresh CPU+8GPU mint per request is expensive (~1.3 s) and the quote
        serializes one-at-a-time, so the nonce path is limited to
        `KUBETEE_FRESH_MINT_LIMIT` per `KUBETEE_FRESH_MINT_WINDOW_S` per key and
        rejected with a SELF-DOCUMENTING 429 beyond (the body + headers name the
        limit AND the `X-KubeTEE-Proof: 1` workaround in-band, so an agent needs
        zero external docs to recover). X-KubeTEE-Proof (proof-of-inference) is
        NOT rate-limited and passes through untouched.

        Returns None to allow; raises HTTPException(429) to reject BEFORE the
        model runs (LiteLLM renders `detail` as the JSON body).
        """
        headers = _pre_call_request_headers(data)
        raw_nonce = _request_header(headers, _NONCE_HEADER)
        if raw_nonce is None:
            return None  # no fresh mint requested — nothing to rate-limit
        # Malformed nonce is handled (and reported) on the response path; do not
        # consume a rate-limit permit here for a request that will be rejected.
        if _validate_nonce(raw_nonce) is None:
            return None

        # Per-key (a virtual key when present; else the bearer token).
        key_id = (
            getattr(user_api_key_dict, "token", None)
            or getattr(user_api_key_dict, "user_api_key", None)
            or "anonymous"
        )
        allowed, retry_after = _fresh_mint_limiter.check(str(key_id))
        if allowed:
            return None

        from fastapi import HTTPException

        raise HTTPException(
            status_code=429,
            detail=kubetee_proof.rate_limit_error(_FRESH_MINT_LIMIT, _FRESH_MINT_WINDOW_S, retry_after),
            headers=kubetee_proof.rate_limit_headers(_FRESH_MINT_LIMIT, _FRESH_MINT_WINDOW_S, retry_after),
        )

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
        nonce = _request_header(headers, _NONCE_HEADER)
        raw_nonce = _validate_nonce(nonce)
        if nonce is not None and raw_nonce is None:
            # Malformed nonce: signal, don't fail the completion.
            return _latin1_headers(
                {"X-KubeTEE-Attestation-Error": "invalid nonce (need 64 hex)"}
            )
        proof_val = (_request_header(headers, _PROOF_HEADER) or "").strip()
        wants_proof = proof_val != ""
        if raw_nonce is None and not wants_proof:
            return None  # no opt-in header — no-op

        out: dict[str, str] = {}
        try:
            if raw_nonce is not None:
                payload = await get_attestation_payload(raw_nonce)
                if payload is None:
                    return _latin1_headers(
                        {"X-KubeTEE-Attestation-Error": "invalid nonce (need 64 hex)"}
                    )
                out.update(_attestation_headers(payload, raw_nonce))
        except Exception as e:
            # The exception text is free-form and may not be latin-1; sanitize.
            return _latin1_headers(
                {"X-KubeTEE-Attestation-Error": f"attestation evidence unavailable: {e}"}
            )

        # The routed backend pod's evidence — fetched ONCE and shared by the
        # identity headers and the proof, so the proof commits to the SAME
        # digest the relay exposes (fresh when a nonce was forwarded, the pod's
        # cached epoch otherwise).
        backend_headers: dict[str, str] = {}
        if raw_nonce is not None or wants_proof:
            backend_headers = await _backend_identity_headers(
                data, litellm_call_info, nonce=raw_nonce
            )
            out.update(backend_headers)

        if wants_proof:
            try:
                out.update(
                    await _proof_headers(
                        backend_headers, data, request_headers, response
                    )
                )
            except Exception as e:
                out["X-KubeTEE-Proof-Error"] = f"proof unavailable: {e}"
        return _latin1_headers(out)


# Resolved by get_instance_fn("kubetee_attestation.kubetee_attestation_logger").
# Singleton instance (instantiated once; __init__ mounts the route).
kubetee_attestation_logger = KubeTEEAttestationLogger()
