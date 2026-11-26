"""KubeTEE NIM GPU evidence collector (NVIDIA Confidential-Computing GPU).

"Get the NIM GPU evidence" = collect, per NVIDIA CC GPU in the backend guest,
the signed SPDM ``GET_MEASUREMENTS`` attestation report and the device
certificate chain, and assemble them (with the CPU platform evidence) into the
composite document that the Trustee / NVIDIA NRAS appraiser consumes.

Wire contract -- mirrors CoCo Trustee
``deps/verifier/src/nvidia/nvat.rs::devices_to_nvat_json`` (the NVAT
``GpuEvidenceSource::from_json_string`` input)::

    [
      {"arch": "HOPPER"|"BLACKWELL", "nonce": "<64-hex>",
       "evidence": "<base64 SPDM report = request || signed response>",
       "certificate": "<PEM device cert chain, leaf-first>"},
      ... one entry per GPU ...
    ]

The SPDM report framing is byte-exact to CoCo Trustee
``deps/verifier/src/nvidia/spdm_request.rs`` (37-byte GET_MEASUREMENTS request,
SPDM 1.1, nonce at bytes [4:36]) and ``report.rs`` (signed data = report minus
the trailing signature; signature = trailing bytes, 96-byte raw r||s for
Hopper). The device transport (SPDM over NVIDIA's nv-attestation toolkit / the
CoCo attestation-agent ``GpuEvidenceSource``) runs in the NIM guest behind the
``DeviceCollector`` seam; every other function here is pure and offline-tested
(``tests/test_gpu_evidence.py``).

This module COLLECTS and SERIALIZE-ONLYs -- it holds no cache, no TTL, and no
verdict. The scheduled (~every 5 min) cache policy and the composite CPU + GPU
appraisal are separate layers built on top of this.

Deploy target: the NIM backend guest (imported by the backend evidence route,
``kubetee_evidence.py``, alongside ``_aa_get_evidence``). The gateway relay
(``kubetee_attestation._normalize_backend_evidence``) passes the resulting
composite through unchanged -- it never re-collects GPU evidence.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Final, Protocol, TypeAlias

# ---------------------------------------------------------------------------
# SPDM 1.1 GET_MEASUREMENTS framing (byte-exact to CoCo Trustee)
# ---------------------------------------------------------------------------
# See deps/verifier/src/nvidia/{spdm_request.rs,report.rs}. Only SPDM 1.1 is
# supported by the Trustee verifier; a different version byte is rejected both
# here (we emit 0x11) and there (decode bails).
SPDM_VERSION_SUPPORTED: Final[int] = 0x11
SPDM_NONCE_SIZE: Final[int] = 32
SPDM_GET_MEASUREMENT_REQUEST_SIZE: Final[int] = 37  # == size_of::<...>()
# DMTF SPDM request_response_code for GET_MEASUREMENTS.
SPDM_GET_MEASUREMENTS: Final[int] = 0xE0
# Param1: request a signed measurement (bit 0 = SIG_INCLUDED per DSP0274 1.1).
SPDM_PARAM1_SIGNATURE_REQUESTED: Final[int] = 0x01
DEFAULT_SIGNATURE_LENGTH: Final[int] = 96  # Hopper raw ECDSA P-384 r||s (48+48)

SCHEMA: Final[str] = "kubetee.gpu-evidence/1"
DEFAULT_ROLE: Final[str] = "nim-terminator"

# Report signature length can differ per architecture (Hopper is 96). The
# collector is parameterized; this map is the known-good default and is what
# the offline vectors pin. A GPU whose architecture needs a different length
# must pass it explicitly rather than guess here.
SIGNATURE_LENGTH_BY_ARCH: Final[dict[str, int]] = {
    "HOPPER": 96,
    "BLACKWELL": 96,
}

Json: TypeAlias = "str | int | float | bool | None | list[Json] | dict[str, Json]"


class GpuEvidenceError(ValueError):
    """Raised for malformed nonce / report / evidence input (fail closed)."""


# ---------------------------------------------------------------------------
# Nonce + request framing
# ---------------------------------------------------------------------------
def normalize_nonce(nonce: str | bytes) -> bytes:
    """Return the 32-byte nonce from a 64-hex string (or raw 32 bytes)."""
    if isinstance(nonce, (bytes, bytearray)):
        raw = bytes(nonce)
        if len(raw) != SPDM_NONCE_SIZE:
            raise GpuEvidenceError(
                f"nonce must be {SPDM_NONCE_SIZE} bytes, got {len(raw)}"
            )
        return raw
    if not isinstance(nonce, str):
        raise GpuEvidenceError("nonce must be a 64-hex string or 32 raw bytes")
    text: Final[str] = nonce.strip().lower()
    if len(text) != SPDM_NONCE_SIZE * 2:
        raise GpuEvidenceError(
            f"nonce must be {SPDM_NONCE_SIZE * 2} hex chars, got {len(text)}"
        )
    try:
        return bytes.fromhex(text)
    except ValueError as exc:  # non-hex
        raise GpuEvidenceError("nonce must be exactly 64 hex characters") from exc


def build_get_measurements_request(
    nonce: str | bytes,
    *,
    param1: int = SPDM_PARAM1_SIGNATURE_REQUESTED,
    param2: int = 0,
    slot_id_param: int = 0,
) -> bytes:
    """The 37-byte SPDM 1.1 GET_MEASUREMENTS request that seeds a GPU report.

    Layout (DSP0274 1.1.1 / CoCo Trustee ``spdm_request.rs``)::

        0     SPDMVersion        1  -> 0x11
        1     RequestResponseCode1  -> 0xE0 (GET_MEASUREMENTS)
        2     Param1             1
        3     Param2             1
        4     Nonce             32  -> caller nonce (freshness / binding)
        36    SlotIDParam        1

    The nonce lives at bytes [4:36] and is what the signed report echoes back;
    a verifier (``report.rs::validate_nonce``) requires an exact match. This is
    the request WE mint -- the GPU's signed response is appended to it to form
    the full report handed to the appraiser.
    """
    n: Final[bytes] = normalize_nonce(nonce)
    req: Final[bytearray] = bytearray()
    req.append(SPDM_VERSION_SUPPORTED)
    req.append(SPDM_GET_MEASUREMENTS)
    req.append(param1 & 0xFF)
    req.append(param2 & 0xFF)
    req.extend(n)  # [4:36]
    req.append(slot_id_param & 0xFF)  # [36]
    if len(req) != SPDM_GET_MEASUREMENT_REQUEST_SIZE:
        raise GpuEvidenceError(
            f"GET_MEASUREMENTS request is {len(req)} bytes, "
            f"expected {SPDM_GET_MEASUREMENT_REQUEST_SIZE}"
        )
    return bytes(req)


def split_report(report: bytes, signature_length: int = DEFAULT_SIGNATURE_LENGTH) -> tuple[bytes, bytes]:
    """Split a GPU report into (signed_data, signature) exactly as Trustee does.

    ``report.rs``: signed_data = report[..report_len - signature_length] and the
    signature is the trailing ``signature_length`` bytes (raw r||s, NOT DER).
    The signed data spans BOTH the request and the measurement response -- the
    GPU signs over the request that carries the nonce, which is what binds the
    caller nonce into the report.
    """
    raw: Final[bytes] = bytes(report)
    if signature_length <= 0 or signature_length >= len(raw):
        raise GpuEvidenceError(
            f"report of {len(raw)} bytes cannot end in a {signature_length}-byte signature"
        )
    return raw[:-signature_length], raw[-signature_length:]


def nonce_in_report(report: bytes) -> bytes:
    """Extract the request nonce from a report's fixed request section.

    The request is the first 37 bytes; the nonce is [4:36] (``spdm_request.rs``).
    Used to self-check that the report we collected echoes the nonce we sent --
    fail closed rather than return a report that binds a different nonce.
    """
    raw: Final[bytes] = bytes(report)
    if len(raw) < SPDM_GET_MEASUREMENT_REQUEST_SIZE:
        raise GpuEvidenceError("report too small to contain a request section")
    if raw[0] != SPDM_VERSION_SUPPORTED:
        raise GpuEvidenceError(
            f"report SPDM version {raw[0]:#04x} not supported "
            f"(expected {SPDM_VERSION_SUPPORTED:#04x})"
        )
    return raw[4:36]


# ---------------------------------------------------------------------------
# Per-device evidence + NVAT serialization
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class DeviceEvidence:
    """One GPU's collected evidence: a signed report + its device cert chain.

    ``evidence`` may be raw report bytes (the common case) or an already
    hex/base64-encoded string from a collector that returns text. ``certificate``
    is the PEM device certificate chain (leaf first), matching the Trustee
    ``NvidiaCertificateChain::decode`` PEM-stack input.
    """

    arch: str
    uuid: str
    evidence: bytes | str
    certificate: str


def _evidence_b64(evidence: bytes | str) -> str:
    """Base64 of the report bytes, mirroring ``devices_to_nvat_json`` exactly.

    CoCo Trustee normalizes a hex string to base64 and passes an already-base64
    string through unchanged. We accept bytes (encoded here) or a str (hex
    decoded then encoded; otherwise passed through as base64).
    """
    if isinstance(evidence, (bytes, bytearray)):
        return base64.b64encode(bytes(evidence)).decode("ascii")
    text: Final[str] = evidence.strip()
    try:  # hex -> bytes -> b64 (same as Rust `hex::decode` arm)
        return base64.b64encode(bytes.fromhex(text)).decode("ascii")
    except ValueError:
        return text  # already base64 (same as Rust fallback arm)


def to_nvat_entry(device: DeviceEvidence, nonce: str | bytes) -> dict[str, str]:
    """One NVAT ``GpuEvidenceSource`` entry for a device."""
    n: Final[bytes] = normalize_nonce(nonce)
    return {
        "arch": device.arch.strip().upper(),
        "nonce": n.hex(),
        "evidence": _evidence_b64(device.evidence),
        "certificate": device.certificate,
    }


def devices_to_nvat_json(devices: list[DeviceEvidence], nonce: str | bytes) -> str:
    """Serialize all collected devices to the NVAT JSON array (Trustee input).

    Byte-equivalent to CoCo Trustee ``nvat.rs::devices_to_nvat_json``: an upper-
    cased ``arch``, a lower-hex ``nonce`` (identical across every entry), the
    base64 ``evidence``, and the verbatim ``certificate``.
    """
    entries: Final[list[dict[str, str]]] = [
        to_nvat_entry(device, nonce) for device in devices
    ]
    return json.dumps(entries, separators=(",", ":"), sort_keys=True)


# ---------------------------------------------------------------------------
# Collection seam (the one live transport -- SPDM over nv-attestation / CoCo AA)
# ---------------------------------------------------------------------------
class DeviceCollector(Protocol):
    """Collects one GPU's evidence inside the NIM guest.

    Implemented against NVIDIA's nv-attestation toolkit / the CoCo
    attestation-agent ``GpuEvidenceSource``. It must:

      * send ``build_get_measurements_request(nonce)`` to GPU ``index``,
      * return the FULL report bytes (request || signed response) and the PEM
        device certificate chain for that GPU.

    Everything framing/serialization related is handled (and tested) here; the
    implementation only moves bytes to and from the device.
    """

    def collect(self, index: int, nonce: bytes) -> DeviceEvidence: ...


def collect_gpu_evidence(
    nonce: str | bytes,
    collector: DeviceCollector,
    count: int,
    arch: str = "HOPPER",
) -> list[DeviceEvidence]:
    """Collect a report from each of ``count`` GPUs, nonce-bound and self-checked.

    Fails closed: if any GPU's report does not echo the requested nonce (or the
    transport raises), the whole collection raises rather than return a partial
    or mis-bound set. The caller (backend evidence route) surfaces that as an
    evidence-unavailable error -- never fabricated GPU evidence.
    """
    n: Final[bytes] = normalize_nonce(nonce)
    devices: list[DeviceEvidence] = []
    for index in range(count):
        device = collector.collect(index, n)
        # Self-check the request section echoes OUR nonce (fail closed). A
        # collector that returns raw bytes carries the request inline; one that
        # returns pre-encoded text is checked in the same way after decode.
        try:
            raw = (
                device.evidence
                if isinstance(device.evidence, (bytes, bytearray))
                else base64.b64decode(_evidence_b64(device.evidence))
            )
            echoed = nonce_in_report(raw)
            if echoed != n:
                raise GpuEvidenceError(
                    f"GPU {device.uuid or index} report binds nonce "
                    f"{echoed.hex()}, not the requested {n.hex()}"
                )
        except GpuEvidenceError:
            raise
        except Exception as exc:  # unparseable report -> fail closed
            raise GpuEvidenceError(
                f"GPU {device.uuid or index} report is not parseable: {exc}"
            ) from exc
        if not device.arch.strip():
            device = DeviceEvidence(
                arch=arch,
                uuid=device.uuid,
                evidence=device.evidence,
                certificate=device.certificate,
            )
        devices.append(device)
    return devices


# ---------------------------------------------------------------------------
# Composite CPU + all-GPU evidence document
# ---------------------------------------------------------------------------
def evidence_digest(gpus_json: str, nonce: str | bytes) -> str:
    """sha256 over the canonical GPU evidence array + the nonce.

    Deterministic and nonce-sensitive: two collections of the same GPUs under
    different nonces digest differently (freshness), and any byte change to a
    report/cert changes the digest (integrity). Binds the whole GPU set with one
    value the appraiser / verifier can pin.
    """
    n: Final[bytes] = normalize_nonce(nonce)
    h = hashlib.sha256()
    h.update(gpus_json.encode("utf-8"))
    h.update(b"\x00")
    h.update(n)
    return "sha256:" + h.hexdigest()


def composite_evidence(
    cpu_evidence: dict[str, Json],
    gpus: list[DeviceEvidence],
    nonce: str | bytes,
    *,
    role: str = DEFAULT_ROLE,
    arch: str = "HOPPER",
) -> dict[str, Json]:
    """Assemble the CPU platform evidence + all-GPU evidence into one document.

    Shape (additive, self-describing -- mirrors the backend TDX/SNP envelope
    discipline so the gateway relay and client branch on ``schema``/``tee``)::

        {"schema": "kubetee.gpu-evidence/1", "tee": "tdx",
         "role": "nim-terminator", "subject": "nim-terminator",
         "nonce": "<64-hex>", "gpu_count": N, "arch": "HOPPER",
         "cpu": {...},                       # the platform (CPU) evidence
         "gpus": [ ...NVAT array... ],       # per-GPU {arch,nonce,evidence,cert}
         "gpus_json": "<canonical gpus array>",   # verbatim bytes to re-hash
         "evidence_digest": "sha256:<hex>"}  # sha256(gpus_json || nonce)

    ``gpus_json`` is served verbatim so a verifier re-derives ``evidence_digest``
    without re-canonicalizing (same discipline as the v1 report_data_statement).
    """
    n: Final[bytes] = normalize_nonce(nonce)
    gpus_json: Final[str] = devices_to_nvat_json(gpus, n)
    return {
        "schema": SCHEMA,
        "tee": "tdx",
        "role": role,
        "subject": role,
        "nonce": n.hex(),
        "gpu_count": len(gpus),
        "arch": arch.strip().upper(),
        "cpu": cpu_evidence,
        "gpus": json.loads(gpus_json),
        "gpus_json": gpus_json,
        "evidence_digest": evidence_digest(gpus_json, n),
    }


def collect_composite(
    cpu_evidence: dict[str, Json],
    nonce: str | bytes,
    collector: DeviceCollector,
    count: int,
    *,
    role: str = DEFAULT_ROLE,
    arch: str = "HOPPER",
) -> dict[str, Json]:
    """Collect all GPU evidence and assemble the composite document.

    The full "get the NIM GPU evidence" entry point: one nonce in, one CPU + N-GPU
    nonce-bound composite out. Collection and assembly only -- caching and
    appraisal are layered on separately.
    """
    gpus = collect_gpu_evidence(nonce, collector, count, arch=arch)
    return composite_evidence(cpu_evidence, gpus, nonce, role=role, arch=arch)
