"""Pinned conformance tests for the kubetee.attestation.v1 binding.

Vectors come from kubetee-subnet/docs/ATTESTATION-SPEC-v1.md section 4
(published 2026-10-23). They are the partner contract, so these assertions
are byte-for-byte on purpose: a mismatch means the published contract
broke, and the spec (not the test) must be revisited with the partners.
"""

from __future__ import annotations

import datetime
import hashlib
import importlib.util
import sys
from pathlib import Path
from typing import Final

import pytest

_MODULE_PATH: Final = (
    Path(__file__).resolve().parents[4]
    / "tools"
    / "kubetee-litellm-overlay"
    / "kubetee_binding.py"
)
_SPEC: Final = importlib.util.spec_from_file_location("kubetee_binding", _MODULE_PATH)
assert _SPEC is not None and _SPEC.loader is not None, f"cannot load {_MODULE_PATH}"
kb: Final = importlib.util.module_from_spec(_SPEC)
sys.modules["kubetee_binding"] = kb
_SPEC.loader.exec_module(kb)

VECTOR_KEYSET: Final = {
    "not_after": "2030-01-01T00:00:00Z",
    "subject": "kubetee.attestation.v1/test-vector",
    "tls_public_keys": ({"domain": "llm.kubetee.ai", "spki_sha256": "0" * 64},),
}
VECTOR_NONCE: Final = "0123456789abcdef" * 4
VECTOR_KEYSET_DIGEST: Final = "sha256:693868b5f94f4dad208e8e37fe93ebf1be212f3451462b079dc9ba828b8d33ea"
VECTOR_STATEMENT: Final = (
    '{"keyset_digest":"sha256:693868b5f94f4dad208e8e37fe93ebf1be212f3451462b079dc9ba828b8d33ea",'
    '"nonce":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",'
    '"purpose":"kubetee.attestation.v1"}'
)
VECTOR_STATEMENT_SHA256: Final = "755d36ae1b2ea98e9bdb32350b7356b75515e4ecae711a198ade29ec325b14f4"


def test_keyset_digest_matches_published_vector() -> None:
    assert kb.keyset_digest(VECTOR_KEYSET) == VECTOR_KEYSET_DIGEST


def test_statement_matches_published_vector() -> None:
    statement: Final = kb.report_data_statement(VECTOR_KEYSET_DIGEST, VECTOR_NONCE)
    assert statement == VECTOR_STATEMENT


def test_statement_sha256_matches_published_vector() -> None:
    digest: Final = hashlib.sha256(kb.report_data_statement(VECTOR_KEYSET_DIGEST, VECTOR_NONCE).encode("utf-8")).hexdigest()
    assert digest == VECTOR_STATEMENT_SHA256


def test_report_data_is_statement_sha256_zero_padded() -> None:
    rd: Final = kb.report_data(VECTOR_STATEMENT)
    assert rd == hashlib.sha256(VECTOR_STATEMENT.encode("utf-8")).digest() + b"\x00" * 32
    assert len(rd) == 64


def test_build_binding_consistent_across_served_statement() -> None:
    binding: Final = kb.build_binding(VECTOR_KEYSET, VECTOR_NONCE.upper())
    assert binding.version == "kubetee.attestation.v1"
    assert binding.keyset_digest == VECTOR_KEYSET_DIGEST
    assert binding.statement == VECTOR_STATEMENT
    assert binding.report_data == hashlib.sha256(binding.statement.encode("utf-8")).digest() + b"\x00" * 32


def test_statement_template_is_fixed_three_keys_in_jcs_order() -> None:
    statement: Final = kb.report_data_statement(VECTOR_KEYSET_DIGEST, VECTOR_NONCE)
    assert statement.startswith('{"keyset_digest":"sha256:')
    assert statement.endswith('","purpose":"kubetee.attestation.v1"}')
    assert statement.count('","') == 2


def test_jcs_object_key_order_is_canonical() -> None:
    shuffled: Final = {
        "tls_public_keys": ({"spki_sha256": "0" * 64, "domain": "llm.kubetee.ai"},),
        "subject": "kubetee.attestation.v1/test-vector",
        "not_after": "2030-01-01T00:00:00Z",
    }
    assert kb.keyset_digest(shuffled) == VECTOR_KEYSET_DIGEST


def test_keyset_tamper_changes_digest() -> None:
    for key, value in (("subject", "other"), ("not_after", "2031-01-01T00:00:00Z")):
        tampered: Final = dict(VECTOR_KEYSET, **{key: value})
        assert kb.keyset_digest(tampered) != VECTOR_KEYSET_DIGEST


def test_spki_tamper_changes_digest() -> None:
    tampered: Final = dict(VECTOR_KEYSET, tls_public_keys=({"domain": "llm.kubetee.ai", "spki_sha256": "1" * 64},))
    assert kb.keyset_digest(tampered) != VECTOR_KEYSET_DIGEST


def test_nonce_changes_report_data() -> None:
    assert kb.build_binding(VECTOR_KEYSET, "ff" * 32).report_data != kb.build_binding(
        VECTOR_KEYSET, VECTOR_NONCE
    ).report_data


def test_normalize_nonce_lowers_and_strips() -> None:
    assert kb.normalize_nonce(" " + VECTOR_NONCE.upper() + " ") == VECTOR_NONCE


def test_normalize_nonce_rejects_malformed() -> None:
    for bad in ("", "0" * 63, "0" * 65, "g" * 64, 64 * ["0"]):
        try:
            kb.normalize_nonce(bad)  # pyright: ignore[reportArgumentType]  # malformed nonces on purpose
        except ValueError:
            continue
        raise AssertionError(f"normalize_nonce accepted malformed nonce: {bad!r}")


def test_jcs_rejects_numbers_bools_null() -> None:
    for bad in (42, True, None, (1,)):
        try:
            kb.jcs(bad)  # pyright: ignore[reportArgumentType]  # unsupported JCS values on purpose
        except TypeError:
            continue
        raise AssertionError(f"jcs accepted unsupported value: {bad!r}")


def test_report_data_statement_rejects_malformed_keyset_digest() -> None:
    for bad in ("", "sha256:xyz", VECTOR_KEYSET_DIGEST.upper(), "sha512:" + "0" * 64):
        try:
            kb.report_data_statement(bad, VECTOR_NONCE)
        except ValueError:
            continue
        raise AssertionError(f"report_data_statement accepted malformed keyset_digest: {bad!r}")


def _self_signed_cert_pem() -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key: Final = ec.generate_private_key(ec.SECP256R1())
    name: Final = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "kubetee-binding-test")])
    cert: Final = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def test_keyset_from_cert_pem_derives_spki_and_not_after() -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    cert_pem: Final = _self_signed_cert_pem()
    keyset: Final = kb.keyset_from_cert_pem(cert_pem, "llm.kubetee.ai")
    cert: Final = x509.load_pem_x509_certificate(cert_pem)
    spki_sha256: Final = hashlib.sha256(
        cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()
    assert keyset["tls_public_keys"] == ({"domain": "llm.kubetee.ai", "spki_sha256": spki_sha256},)
    assert keyset["not_after"] == "2030-01-01T00:00:00Z"
    assert keyset["subject"] == "kubetee.attestation.v1/llm.kubetee.ai"
    assert keyset["signing_keys"] == () and keyset["e2ee_keys"] == ()


def test_keyset_from_cert_pem_uses_leaf_of_chain() -> None:
    leaf_pem: Final = _self_signed_cert_pem()
    chain_pem: Final = leaf_pem + _self_signed_cert_pem()
    assert kb.keyset_from_cert_pem(chain_pem, "llm.kubetee.ai") == kb.keyset_from_cert_pem(leaf_pem, "llm.kubetee.ai")


def test_keyset_from_cert_pem_digest_changes_with_domain() -> None:
    cert_pem: Final = _self_signed_cert_pem()
    assert kb.keyset_digest(kb.keyset_from_cert_pem(cert_pem, "a.example")) != kb.keyset_digest(
        kb.keyset_from_cert_pem(cert_pem, "b.example")
    )


# --- legacy construction (the wire default until the gm-miner switch) -----

# Live production vector (2026-10-24): GET /v1/attestation?nonce=<NONCE> ->
# quote REPORTDATA (TDREPORT offset 568) == SHA-512(ascii nonce).
LIVE_LEGACY_NONCE: Final = "3161321c1eea48b1d53e8b89490d8a12c5abafeacc2dee2cada12e80569321e4"
LIVE_LEGACY_REPORT_DATA: Final = (
    "840049a67f3c900663bf274975b2419f843c4a01a4c08149f410c3d338a9c6a0"
    "54667dd1493c4909fb1b42b90e243f68fab96ac574d588e9ea47823bcce54a5b"
)


def test_legacy_report_data_is_sha512_of_ascii_nonce() -> None:
    # Byte-exact against a LIVE production quote (2026-10-24):
    # GET /v1/attestation?nonce=<LIVE_NONCE> -> quote REPORTDATA (TDREPORT
    # offset 568) == SHA-512(ascii nonce), 64 bytes, no padding. This is
    # also byte-exact with the deployed gm-miner verifier
    # (Sha512::digest(nonce.as_bytes()) over the nonce it sent).
    live = kb.legacy_report_data(LIVE_LEGACY_NONCE)
    assert live == hashlib.sha512(LIVE_LEGACY_NONCE.encode("ascii")).digest()
    assert live.hex() == LIVE_LEGACY_REPORT_DATA
    assert len(live) == 64


def test_legacy_report_data_normalizes_nonce_case() -> None:
    # The verifier hashes the nonce in the casing it sent (lowercase hex);
    # normalize so an upper-cased caller value cannot shift the binding.
    assert kb.legacy_report_data(LIVE_LEGACY_NONCE.upper()) == kb.legacy_report_data(
        LIVE_LEGACY_NONCE
    )


def test_legacy_report_data_rejects_malformed_nonce() -> None:
    with pytest.raises(ValueError, match="nonce"):
        kb.legacy_report_data("not-a-nonce")


def test_legacy_report_data_is_not_the_v1_binding() -> None:
    # The two constructions must never collide: a v1 quote must not verify
    # under the legacy check and vice versa (the verifier fails mixed shapes
    # closed — anti-downgrade).
    nonce: Final = LIVE_LEGACY_NONCE
    keyset: Final = {
        "subject": "kubetee.attestation.v1/llm.kubetee.ai",
        "not_after": "2030-01-01T00:00:00Z",
        "tls_public_keys": (
            {"domain": "llm.kubetee.ai", "spki_sha256": "0" * 64},
        ),
        "signing_keys": (),
        "e2ee_keys": (),
    }
    v1 = kb.build_binding(keyset, nonce).report_data
    assert v1 != kb.legacy_report_data(nonce)
