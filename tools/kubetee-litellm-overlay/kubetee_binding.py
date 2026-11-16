"""KubeTEE attestation binding, kubetee.attestation.v1.

Construction (kubetee-subnet/docs/ATTESTATION-SPEC-v1.md section 4, the
partner contract). REPORTDATA is SHA-256 of the JCS statement followed by
32 zero bytes (64 total), and the statement is this fixed template:

    {"keyset_digest":"sha256:<hex>","nonce":"<64-hex>","purpose":"kubetee.attestation.v1"}

The statement string is served verbatim as bindings.report_data_statement,
so a verifier hashes those exact bytes and compares them to the quote's
REPORTDATA (offset 568, TDREPORT1.6 layout). keyset_digest covers the
served keyset (spec section 5); the verifier recomputes it from the served
keyset, never from the response alone. Conformance vectors in spec
section 4 are pinned by tests/test_litellm/tools/test_kubetee_binding.py.

JCS here covers RFC 8785 for the attestation input class only: objects,
arrays, and well-formed strings, with object keys sorted by UTF-16 code
units and ECMA-262 string serialization. Numbers, booleans, and null are
rejected because the attestation input class never contains them.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, TypeAlias

PURPOSE: Final = "kubetee.attestation.v1"
VERSION: Final = "kubetee.attestation.v1"

# The legacy construction — the WIRE DEFAULT until the gm-miner switch PR
# (taostat/gm-miner) is accepted upstream and redeployed. The deployed
# verifier checks exactly this: SHA-512 over the ASCII nonce hex string
# (64 bytes, no padding). Byte-verified against a live production quote
# (2026-10-24, nonce 3161321c…e4). `report_data_input` names it
# "sha512(nonce)" on every legacy response.
LEGACY_REPORT_DATA_INPUT: Final = "sha512(nonce)"

JsonTree: TypeAlias = "str | tuple[JsonTree, ...] | Mapping[str, JsonTree]"

_NONCE_RE: Final = re.compile(r"^[0-9a-f]{64}$")
_KEYSET_DIGEST_RE: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
_PEM_BLOCK_END: Final = b"-----END CERTIFICATE-----"


def _jcs_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def jcs(obj: JsonTree) -> str:
    """RFC 8785 canonical JSON string for the attestation input class."""
    if isinstance(obj, str):
        return _jcs_string(obj)
    if isinstance(obj, Mapping):
        items: Final = sorted(obj.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_jcs_string(k) + ":" + jcs(v) for k, v in items) + "}"
    if isinstance(obj, tuple):
        return "[" + ",".join(jcs(v) for v in obj) + "]"
    raise TypeError(
        f"JCS: unsupported type {type(obj).__name__}; the attestation input "
        "class is objects, arrays, and well-formed strings only"
    )


def normalize_nonce(nonce: str) -> str:
    """Lowercased 64-hex nonce, or ValueError."""
    if not isinstance(nonce, str):
        raise ValueError("nonce must be a string of 64 hex characters")
    normalized: Final = nonce.strip().lower()
    if not _NONCE_RE.match(normalized):
        raise ValueError("nonce must be exactly 64 hex characters")
    return normalized


def keyset_digest(keyset: Mapping[str, JsonTree]) -> str:
    """sha256:<hex> over JCS(keyset), the value bound via report_data."""
    digest: Final = hashlib.sha256(jcs(keyset).encode("utf-8")).hexdigest()
    return "sha256:" + digest


def report_data_statement(keyset_digest_value: str, nonce: str) -> str:
    """The fixed-template statement, also served verbatim to verifiers."""
    if not isinstance(keyset_digest_value, str) or not _KEYSET_DIGEST_RE.match(keyset_digest_value):
        raise ValueError("keyset_digest must match 'sha256:<64 hex>'")
    statement: Final[Mapping[str, str]] = {
        "keyset_digest": keyset_digest_value,
        "nonce": normalize_nonce(nonce),
        "purpose": PURPOSE,
    }
    return jcs(statement)


def legacy_report_data(nonce: str) -> bytes:
    """The legacy (pre-flip) binding: SHA-512 over the ASCII nonce (64 B).

    This is what the deployed gm-miner verifies
    (``Sha512::digest(nonce.as_bytes())`` over the nonce string it sent) and
    what a live production quote's REPORTDATA carries — byte-exact both
    sides (pinned by tests against a recorded live quote). The nonce is
    normalized (lowercased) first: the verifier hashes the nonce in the
    casing it sent, which is lowercase hex.
    """
    return hashlib.sha512(normalize_nonce(nonce).encode("ascii")).digest()


def report_data(statement: str) -> bytes:
    """SHA-256 of the exact statement bytes, zero-padded to 64 bytes.

    Never re-canonicalizes: the verifier hashes the served
    bindings.report_data_statement bytes the same way.
    """
    return hashlib.sha256(statement.encode("utf-8")).digest() + b"\x00" * 32


@dataclass(frozen=True, slots=True)
class Binding:
    version: str
    keyset_digest: str
    statement: str
    report_data: bytes


def build_binding(keyset: Mapping[str, JsonTree], nonce: str) -> Binding:
    """Full construction: bind the served keyset and the caller nonce."""
    digest: Final = keyset_digest(keyset)
    statement: Final = report_data_statement(digest, nonce)
    return Binding(
        version=VERSION,
        keyset_digest=digest,
        statement=statement,
        report_data=report_data(statement),
    )


def keyset_from_cert_pem(cert_pem: bytes, domain: str) -> dict[str, JsonTree]:
    """JSON-serializable served keyset (spec section 5) from the TLS leaf.

    tls.crt may carry leaf + intermediates; only the leaf (first PEM block)
    holds the serving key. spki_sha256 is the SHA-256 of the DER
    SubjectPublicKeyInfo. signing_keys and e2ee_keys stay empty until the
    attest-surface bundle carries them. Returns a plain dict because this
    is the wire object (json.dumps cannot encode MappingProxyType).
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    leaf_pem: Final = cert_pem.split(_PEM_BLOCK_END)[0] + _PEM_BLOCK_END
    cert: Final = x509.load_pem_x509_certificate(leaf_pem)
    spki_der: Final = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "subject": f"{VERSION}/{domain}",
        "not_after": cert.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tls_public_keys": ({"domain": domain, "spki_sha256": hashlib.sha256(spki_der).hexdigest()},),
        "signing_keys": (),
        "e2ee_keys": (),
    }
