"""Trustee EAR / AR4SI appraisal for the KubeTEE attestation bundle.

Standards core (plan ``ear-in-report``): the bundle's ``appraisal`` block
carries Trustee's **EAR** (EAT + AR4SI trustworthiness vector) alongside the
raw evidence — the *results* leg of the RATS map (evidence = TDX quote,
reference values = CoRIM, results = EAR/AR4SI).

Why the appraisal is minted per boot (and what it does and does not bind)
------------------------------------------------------------------------
The CoCo AS checks runtime data against the quote's REPORTDATA with
``RuntimeData::Raw`` compared 1:1 (``regularize_data`` only pads), but the
KBS RCAR client (``/kbs/v0/auth`` + ``/kbs/v0/attest``) force-hashes
``{"additional-evidence", "nonce", "tee-pubkey"}`` — a construction that
collides with the v1 statement binding carried by the per-request quote.
So ``appraisal.ear_token`` is minted **once per boot** over that RCAR
binding and serves purely as the platform appraisal:

- it appraises THIS TD's MRTD/RTMR0-3/MRCONFIGID and its initdata
  (``role`` + ``agent_policy_claims``) — fixed for the boot's lifetime;
- it does **not** bind the per-request nonce. That is the v1 statement's
  job (``bindings.report_data_statement`` in REPORTDATA, spec §5 item 2).
  The two mechanisms are complementary: spec §5 item 4 ("Appraisal")
  versus item 2 ("Binding").

The EAR is signed by Trustee's token key; verifiers check it against the
KBS JWKS (``/kbs/v0/attestation/keys``), never against anything the guest
says. The RCAR mint also binds a **per-boot key** (its ``TeePubKey::EC`` JWK
is the hashed ``tee-pubkey``) — under the attestation-gated signer design
that is the east-west identity key whose signed certificate gates backend
access, so the appraisal is linked to the key that carries authorization.

Wire facts (pinned against the vendored Trustee, CoCo-trustee @ v0.22.0):

- ``Attestation`` is kebab-case at the top level (``runtime-data``,
  ``tee-evidence``, ``init-data``) while ``CompositeEvidence`` is
  snake_case (``primary_evidence``, ``additional_evidence``) and
  ``RuntimeData`` is ``{"nonce", "tee-pubkey"}``.
- The primary runtime-data map hashed into REPORTDATA is
  ``{"additional-evidence": "", "nonce": …, "tee-pubkey": {…}}`` (backend.rs),
  canonicalized RFC 8785 JCS and SHA-384'd (48 bytes) then zero-padded to
  64 by the verifier. ``kubetee_binding.jcs`` is RFC 8785 for the strings /
  objects / arrays attestation input class and is pinned over the RCAR map by
  ``tests/test_litellm/tools/kubetee-litellm-overlay/test_kubetee_ear.py``
  (SHA-384 ``cf82398c…2376d`` + 16 zero bytes). The AS's own canonicalization
  vector (``{"a":"test","b":1,"c":{"d":"e"}}`` → ``e71ce8e7…870c3``,
  attestation-service/src/lib.rs) carries a **number** and so is outside this
  input class — it is the RFC 8785 equivalence reference for the AS, not a
  runnable vector here (``jcs`` rejects numbers on purpose).
- KBS protocol version is exact-match ``0.4.0`` (KBS_MINOR_VERSION in
  backend.rs; live-probed against https://kbs.kubetee.ai 2026-10-24).

AR4SI group → partner claim mapping (spec §1) is exposed by ``ar4si()`` so
adapters never parse the JWT by hand:

    executables   -> serving_software_known_good
    configuration -> tcb_up_to_date
    environment   -> os_known_good
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import tomllib
from dataclasses import dataclass
from typing import Any, Final

from kubetee_binding import jcs

KBS_BASE: Final = os.environ.get("KUBETEE_KBS_BASE", "https://kbs.kubetee.ai")
KBS_PROTOCOL_VERSION: Final = os.environ.get("KUBETEE_KBS_PROTOCOL_VERSION", "0.4.0")
CDH_BASE: Final = os.environ.get("KUBETEE_CDH_BASE", "http://127.0.0.1:8006")
# The measured initdata reaches the container as the cc_init_data annotation
# (downward API: KUBETEE_INITDATA_B64). A file path override exists for
# setups that mount the guest's /run/confidential-containers instead.
INITDATA_B64_ENV: Final = "KUBETEE_INITDATA_B64"
INITDATA_TOML_PATH: Final = os.environ.get(
    "KUBETEE_INITDATA_PATH", "/run/confidential-containers/initdata/initdata.toml"
)
EAR_CACHE_PATH: Final = os.environ.get("KUBETEE_EAR_CACHE", "/run/kubetee-eastwest/boot-ear.jwt")

# AR4SI group -> KubeTEE claim name (the partner adapter contract, spec §1).
AR4SI_CLAIM_MAP: Final[dict[str, str]] = {
    "executables": "serving_software_known_good",
    "configuration": "tcb_up_to_date",
    "environment": "os_known_good",
}

INITDATA_FILE_KEYS: Final[tuple[str, ...]] = ("aa.toml", "cdh.toml", "policy.rego")


class EarError(RuntimeError):
    """Raised when a Trustee EAR cannot be minted or parsed."""


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64u_decode(value: str) -> bytes:
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


# --- the RCAR runtime-data construction (byte-exact) ------------------------


def rcar_runtime_data_json(nonce: str, tee_pubkey: dict[str, str]) -> dict[str, Any]:
    """The exact JSON the KBS hashes for the primary TDX evidence.

    Mirrors ``kbs/src/attestation/backend.rs``::

        primary_runtime_data = {"tee-pubkey": …, "nonce": …,
                                "additional-evidence": …}

    with ``additional-evidence` an empty string for a CPU-only TDX guest.
    """
    return {
        "additional-evidence": "",
        "nonce": nonce,
        "tee-pubkey": tee_pubkey,
    }


def rcar_report_data(runtime_data_json: dict[str, Any]) -> bytes:
    """REPORTDATA for the RCAR mint: SHA-384 over the JCS, zero-padded to 64.

    The CoCo AS computes ``HashAlgorithm::Sha384.digest(serialize_canon_json(...))``
    (48 bytes) and compares it to the quote's 64-byte REPORTDATA after
    ``regularize_data(..., 64)`` — 48 bytes of digest + 16 zero bytes.
    """
    digest = hashlib.sha384(jcs(runtime_data_json).encode("utf-8")).digest()
    return digest + b"\x00" * 16


# --- initdata (evidence.vm_config source) -----------------------------------


def load_initdata_text() -> str | None:
    """The measured initdata TOML as exact text, from the annotation or file."""
    encoded = os.environ.get(INITDATA_B64_ENV)
    if encoded:
        try:
            return gzip.decompress(_b64u_decode(encoded.strip())).decode("utf-8")
        except Exception:
            return None
    try:
        with open(INITDATA_TOML_PATH, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None


def load_initdata() -> dict[str, Any] | None:
    """The initdata TOML parsed (``tomllib``), or None when unavailable."""
    text = load_initdata_text()
    if text is None:
        return None
    try:
        return tomllib.loads(text)
    except Exception:
        return None


def initdata_sha384() -> str | None:
    """``MRCONFIGID`` source: SHA-384 over the exact initdata TOML bytes."""
    text = load_initdata_text()
    if text is None:
        return None
    return hashlib.sha384(text.encode("utf-8")).hexdigest()


def tee_pubkey_of(key: Any) -> dict[str, str]:
    """The ``TeePubKey`` JWK (kbs-types) of the RCAR ``tee-pubkey`` input.

    Both kbs-types variants are produced (``TeePubKey`` is ``#[serde(tag =
    "kty")]``): an EC P-256 key → ``TeePubKey::EC``, an RSA key →
    ``TeePubKey::RSA`` (wire names ``n``/``e`` per the serde renames in
    kbs-types/src/lib.rs). The KBS runtime-data map accepts either.

    The bound key is the EAST-WEST identity key whose cert carries
    authorization (see ``bootstrap_ear_from_key_pem``): that key is fetched
    from KBS as **RSA** (gen-certs.sh: ``openssl genrsa``) while an in-guest
    per-boot key is P-256 — so both arms are live paths, not defensive ones.
    The RSA arm is why ``appraisal`` was permanently absent before
    2026-10-27: this helper was EC-only and raised
    ``AttributeError: … 'RSAPublicNumbers' object has no attribute 'x'`` on
    the real east-west key.

    Lives here (not in the retired ``kubetee_serving_cert``) because the RCAR
    runtime-data construction above consumes it.
    """
    numbers = key.public_key().public_numbers()
    if hasattr(numbers, "x") and hasattr(numbers, "y"):
        # Only P-256 (RFC 7518 ES256) is a supported EC arm — a wider curve
        # would serialize to the wrong coordinate width and silently produce
        # a non-verifiable JWK. Reject it explicitly instead.
        if numbers.x.bit_length() > 256 or numbers.y.bit_length() > 256:
            raise EarError("tee-pubkey EC key must be P-256 (ES256)")
        size = 32  # P-256 coordinate octet strings are fixed 32 bytes (RFC 7518)
        return {
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "x": _b64u(numbers.x.to_bytes(size, "big")),
            "y": _b64u(numbers.y.to_bytes(size, "big")),
        }
    if hasattr(numbers, "n") and hasattr(numbers, "e"):
        return {
            "kty": "RSA",
            "alg": "RS256",
            "n": _b64u(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
            "e": _b64u(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
        }
    raise EarError(f"unsupported tee-pubkey key type: {type(key.public_key()).__name__}")


def agent_policy_claims(rego_text: str) -> Any | None:
    """Mirror of the AS's ``extract_policy_data`` (attestation-service/src/lib.rs).

    The ``policy_data`` block must be the last thing in the rego file and
    pure JSON after the brace — the same constraint the AS imposes (its
    ``find()`` matches the declaration literal, so it may not appear in a
    comment above the block).
    """
    marker = "policy_data := {"
    idx = rego_text.find(marker)
    if idx < 0:
        return None
    json_start = idx + len(marker) - 1
    try:
        return json.loads(rego_text[json_start:])
    except Exception:
        return None


def vm_config() -> dict[str, Any] | None:
    """``evidence.vm_config`` — the composition anchor a verifier diffs.

    Self-reported content is fine here: the verifier recomputes
    ``SHA-384(initdata)`` over these files and requires the quote's
    MRCONFIGID to match (spec §5 item 3), so a lie fails the quote check.
    """
    initdata = load_initdata()
    if initdata is None:
        return None
    data = initdata.get("data")
    out: dict[str, Any] = {
        "algorithm": initdata.get("algorithm", "sha384"),
        "version": initdata.get("version", "0.1.0"),
    }
    if isinstance(data, dict):
        out["role"] = data.get("role")
        out["files"] = {k: data[k] for k in INITDATA_FILE_KEYS if k in data}
        claims = agent_policy_claims(data.get("policy.rego", ""))
        if claims is not None:
            out["agent_policy_claims"] = claims
    sha = initdata_sha384()
    if sha is not None:
        out["initdata_sha384"] = sha
    return out


# --- EAR parsing (the EAR is a JWS; signature checks belong to the verifier) -


def decode_ear_claims(ear_token: str) -> dict[str, Any]:
    """Decode the EAR JWT payload claims."""
    try:
        _header, payload, _sig = ear_token.split(".")
    except ValueError as error:
        raise EarError("EAR token is not a JWS compact serialization") from error
    try:
        return json.loads(_b64u_decode(payload))
    except Exception as error:
        raise EarError("EAR payload is not JSON") from error


def ar4si(claims: dict[str, Any]) -> dict[str, Any] | None:
    """The AR4SI trustworthiness vector plus the partner claim mapping."""
    vector: dict[str, Any] = {}
    status: str | None = None

    def walk(node: Any) -> None:
        nonlocal status
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "ear.trustworthiness-vector" and isinstance(value, dict):
                    vector.update(value)
                elif key == "ear.status" and isinstance(value, str):
                    status = value
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(claims)
    if not vector and status is None:
        return None
    mapped = {
        AR4SI_CLAIM_MAP[group]: vector[group]
        for group in AR4SI_CLAIM_MAP
        if group in vector
    }
    out: dict[str, Any] = {}
    if status is not None:
        out["status"] = status
    if vector:
        out["trustworthiness_vector"] = vector
    if mapped:
        out["claims"] = mapped
    return out or None


def appraisal(ear_token: str | None) -> dict[str, Any] | None:
    """The bundle's ``appraisal`` block, or None when no EAR was captured."""
    if not ear_token:
        return None
    block: dict[str, Any] = {"ear_token": ear_token}
    try:
        claims = decode_ear_claims(ear_token)
    except EarError:
        return block
    vector = ar4si(claims)
    if vector is not None:
        block["ar4si"] = vector
    return block


def load_cached_ear() -> str | None:
    """The boot-time EAR captured during startup, if the cache file exists."""
    try:
        with open(EAR_CACHE_PATH, encoding="utf-8") as f:
            value = f.read().strip()
    except OSError:
        return None
    return value or None


# --- minting the boot-time EAR (RCAR against KBS) ---------------------------


@dataclass(frozen=True, slots=True)
class BootEar:
    token: str
    report_data: bytes


async def mint_boot_ear(tee_pubkey: dict[str, str]) -> BootEar:
    """Run one RCAR exchange to obtain a Trustee EAR for this boot.

    ``tee_pubkey`` is the kbs-types ``TeePubKey::EC`` JWK of the **per-boot
    identity key** (the east-west key under the attestation-gated signer
    design), so the appraisal is linked to the key that carries
    authorization. [``tee_pubkey_of``](#tee_pubkey_of) formats it from the
    key object.
    """
    import httpx

    async with httpx.AsyncClient(timeout=30.0) as http:
        auth = await http.post(
            f"{KBS_BASE}/kbs/v0/auth",
            json={"version": KBS_PROTOCOL_VERSION, "tee": "tdx", "extra-params": ""},
        )
        auth.raise_for_status()
        challenge = auth.json()
        nonce = challenge["nonce"]
        cookies = dict(auth.cookies)

        runtime_data = rcar_runtime_data_json(nonce, tee_pubkey)
        report_data = rcar_report_data(runtime_data)
        evidence = await _aa_evidence(report_data)

        # kbs-types wire: Attestation is kebab-case at the top level,
        # CompositeEvidence snake_case inside (pinned above).
        attestation: dict[str, Any] = {
            "runtime-data": {"nonce": nonce, "tee-pubkey": tee_pubkey},
            "tee-evidence": {
                "primary_evidence": evidence,
                "additional_evidence": "",
            },
        }
        initdata_text = load_initdata_text()
        if initdata_text is not None:
            attestation["init-data"] = {"format": "toml", "body": initdata_text}

        resp = await http.post(
            f"{KBS_BASE}/kbs/v0/attest", json=attestation, cookies=cookies
        )
        resp.raise_for_status()
        token = resp.json().get("token")
        if not token:
            raise EarError("KBS /kbs/v0/attest returned no attestation token")
        return BootEar(token=token, report_data=report_data)


async def _aa_evidence(report_data: bytes) -> dict[str, Any]:
    """Mint a TDX quote whose REPORTDATA is ``report_data`` (64 bytes)."""
    import httpx

    url = f"{CDH_BASE}/aa/evidence?runtime_data={_b64u(report_data)}&encoding=base64"
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        return json.loads(resp.content)


async def bootstrap_ear(tee_pubkey: dict[str, str]) -> str | None:
    """Mint and cache the boot-time EAR. Best-effort: None on any failure.

    The appraisal is additive — the quote and its v1 binding stand without
    it — so a Trustee outage degrades ``appraisal`` to absent rather than
    taking the gateway down. East-west identity provisioning, by contrast,
    is fail-closed (``kubetee_eastwest``; the attestation-gated signer
    follow-up makes it per-boot).
    """
    try:
        boot = await mint_boot_ear(tee_pubkey)
    except Exception:
        return None
    try:
        os.makedirs(os.path.dirname(EAR_CACHE_PATH), mode=0o700, exist_ok=True)
        with open(EAR_CACHE_PATH, "w", encoding="utf-8") as f:
            f.write(boot.token)
        os.chmod(EAR_CACHE_PATH, 0o600)
    except OSError:
        pass
    return boot.token


def tee_pubkey_from_key_pem(tls_key_pem: bytes) -> dict[str, str] | None:
    """``tee_pubkey_of`` over an east-west PEM private key (best-effort, None).

    The east-west identity key arrives as TLS PEM (``tls.key`` from
    ``kubetee_eastwest``); the RCAR mint wants the kbs-types ``TeePubKey``
    JWK. Never raises — the appraisal is additive.
    """
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    try:
        return tee_pubkey_of(load_pem_private_key(tls_key_pem, password=None))
    except Exception:
        return None
