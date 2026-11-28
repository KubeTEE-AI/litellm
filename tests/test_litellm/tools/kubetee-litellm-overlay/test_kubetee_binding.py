"""Pinned conformance tests for the kubetee.attestation.v2 binding.

v2-only: the legacy kubetee.attestation.v1 construction (SHA-256 JCS
statement) and the older SHA-512(nonce) derivation were hard-retired and
removed from the module, so there are no v1 functions left to exercise here.

The v2 key-attestation vector is shared with the Rust verifier
(kubetee-attestation-verifier tests/phase6_failclosed.rs) and gm-miner — the
SAME hex on both sides is the cross-language known-answer test for Phase 6.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import importlib.util
import json
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

# Phase 6 vector — the cross-language KAT (Rust: report_data_v2_vector).
V2_PKIX: Final = bytes.fromhex(
    "302a300506032b6570032100" + "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)
V2_NONCE: Final = bytes([0xAA] * 32)
V2_NONCE_HEX: Final = V2_NONCE.hex()  # the statement's nonce field (64 hex)
V2_CONTEXT: Final = "kubetee-test-context"
V2_PREIMAGE_TAIL_SHA384: Final = (
    "7c7f82da79e64d00bb228bf3bd7075ea31b938759d00162f1f1d83021f245e24eff25929ec5761309dbbc014119dc4c0"
)
V2_REPORT_DATA: Final = bytes.fromhex(V2_PREIMAGE_TAIL_SHA384) + b"\x00" * 16

VECTOR_KEYSET: Final = {
    "not_after": "2030-01-01T00:00:00Z",
    "subject": "kubetee.attestation.v2/test-vector",
    "tls_public_keys": ({"domain": "llm.kubetee.ai", "spki_sha256": "0" * 64},),
}
VECTOR_KEYSET_DIGEST: Final = "sha256:7a0aaf897b9ab66db76d186bfcb7f13aaa64f6e7cc3ec6737b07fbaf79be659c"


def test_keyset_digest_matches_published_vector() -> None:
    assert kb.keyset_digest(VECTOR_KEYSET) == VECTOR_KEYSET_DIGEST


def test_jcs_object_key_order_is_canonical() -> None:
    shuffled: Final = {
        "tls_public_keys": ({"spki_sha256": "0" * 64, "domain": "llm.kubetee.ai"},),
        "subject": "kubetee.attestation.v2/test-vector",
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
    assert kb.build_binding_v2(
        V2_PKIX, VECTOR_KEYSET, "ff" * 32, V2_CONTEXT
    ).report_data != kb.build_binding_v2(
        V2_PKIX, VECTOR_KEYSET, V2_NONCE_HEX, V2_CONTEXT
    ).report_data


def test_normalize_nonce_lowers_and_strips() -> None:
    assert kb.normalize_nonce(" " + V2_NONCE_HEX.upper() + " ") == V2_NONCE_HEX


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


def test_report_data_statement_v2_rejects_malformed_keyset_digest() -> None:
    for bad in ("", "sha256:xyz", VECTOR_KEYSET_DIGEST.upper(), "sha512:" + "0" * 64):
        try:
            kb.report_data_statement_v2(bad, V2_NONCE_HEX, "AQIDBA", V2_CONTEXT)
        except ValueError:
            continue
        raise AssertionError(f"report_data_statement_v2 accepted malformed keyset_digest: {bad!r}")


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
    assert keyset["subject"] == "kubetee.attestation.v2/llm.kubetee.ai"
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


# ---------------------------------------------------------------------------
# kubetee.attestation.v2 key-attestation binding (the only construction)
# ---------------------------------------------------------------------------


def test_v2_report_data_matches_rust_kat() -> None:
    """Cross-language KAT: identical hex in the Rust verifier's test."""
    assert kb.report_data_v2(V2_PKIX, V2_NONCE, V2_CONTEXT) == V2_REPORT_DATA


def test_v2_preimage_framing_is_length_prefixed() -> None:
    preimage: Final = kb.report_data_preimage_v2(V2_PKIX, V2_NONCE, V2_CONTEXT)
    assert preimage.startswith(kb.KEY_ATTESTATION_TAG)
    offset = len(kb.KEY_ATTESTATION_TAG)
    for part in (V2_PKIX, V2_NONCE, V2_CONTEXT.encode("ascii")):
        length = int.from_bytes(preimage[offset : offset + 8], "big")
        assert length == len(part)
        offset += 8
        assert preimage[offset : offset + length] == part
        offset += length
    assert offset == len(preimage)


def test_v2_report_data_is_64_bytes_with_16_zero_padding() -> None:
    rd: Final = kb.report_data_v2(V2_PKIX, V2_NONCE, V2_CONTEXT)
    assert len(rd) == 64
    assert rd[48:] == b"\x00" * 16


def test_v2_rejects_malformed_inputs_fails_closed() -> None:
    with pytest.raises(ValueError):
        kb.report_data_v2(b"short", V2_NONCE, V2_CONTEXT)
    with pytest.raises(ValueError):
        kb.report_data_v2(V2_PKIX, b"short", V2_CONTEXT)
    with pytest.raises(ValueError):
        kb.report_data_v2(V2_PKIX, V2_NONCE, "context\nwith-newline")
    with pytest.raises(ValueError):
        kb.report_data_v2(V2_PKIX, V2_NONCE, "x" * 129)


def test_v2_binding_served_inputs_reproduce_report_data() -> None:
    keyset: Final = {
        "subject": "kubetee.attestation.v2/llm.kubetee.ai",
        "not_after": "2027-01-01T00:00:00Z",
        "tls_public_keys": ({"domain": "llm.kubetee.ai", "spki_sha256": "aa" * 32},),
        "signing_keys": (),
        "e2ee_keys": (),
    }
    binding: Final = kb.build_binding_v2(V2_PKIX, keyset, V2_NONCE_HEX.upper(), V2_CONTEXT)
    assert binding.version == "kubetee.attestation.v2"
    # The statement is the canonical JCS of the served binding inputs (the
    # consumer re-derives it field-by-field and rejects any divergence).
    fields: Final = json.loads(binding.statement)
    assert fields["purpose"] == "kubetee.attestation.v2"
    assert fields["context"] == V2_CONTEXT
    assert fields["nonce"] == V2_NONCE_HEX  # normalized lowercase
    assert fields["keyset_digest"] == binding.keyset_digest
    assert fields["pkix_pubkey_b64url"] == base64.urlsafe_b64encode(V2_PKIX).decode().rstrip("=")
    assert kb.report_data_statement_v2(
        fields["keyset_digest"], fields["nonce"], fields["pkix_pubkey_b64url"], fields["context"]
    ) == binding.statement
    # And the quote commitment derives from exactly those statement fields.
    padding: Final = "=" * (-len(fields["pkix_pubkey_b64url"]) % 4)
    pkix: Final = base64.urlsafe_b64decode(fields["pkix_pubkey_b64url"] + padding)
    nonce: Final = bytes.fromhex(fields["nonce"])
    assert kb.report_data_v2(pkix, nonce, fields["context"]) == binding.report_data


def test_v2_statement_matches_rust_jcs_kat() -> None:
    """Cross-language KAT: identical literal in the Rust verifier's test."""
    assert (
        kb.report_data_statement_v2(
            "sha256:" + "ab" * 32, "aa" * 32, "AQIDBA", "role=nim-terminator"
        )
        == '{"context":"role=nim-terminator",'
        '"keyset_digest":"sha256:' + "ab" * 32 + '",'
        '"nonce":"' + "aa" * 32 + '",'
        '"pkix_pubkey_b64url":"AQIDBA",'
        '"purpose":"kubetee.attestation.v2"}'
    )


def test_v2_ephemeral_key_possession_signature_verifies_under_bound_key() -> None:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_der_public_key,
    )

    import importlib.util

    path = Path(__file__).resolve().parents[4] / "tools" / "kubetee-litellm-overlay" / "kubetee_ephemeral.py"
    spec = importlib.util.spec_from_file_location("kubetee_ephemeral", path)
    assert spec is not None and spec.loader is not None
    ke = importlib.util.module_from_spec(spec)
    sys.modules["kubetee_ephemeral"] = ke  # dataclasses resolve cls via sys.modules
    spec.loader.exec_module(ke)

    eph = ke.boot_key("llm.kubetee.ai")
    # per-boot: same object on repeat access (custody is one key per boot)
    assert ke.boot_key("llm.kubetee.ai") is eph

    rd = kb.report_data_v2(eph.pkix_pubkey, V2_NONCE, V2_CONTEXT)
    sig, alg = eph.possession_signature(rd)
    assert alg == "ecdsa-secp256r1-sha256"
    # the signature verifies ONLY under the key whose SPKI the quote bound
    bound_key = load_der_public_key(eph.pkix_pubkey)
    bound_key.verify(sig, rd, ec.ECDSA(hashes.SHA256()))
    # and the served public bytes round-trip to the same key
    assert (
        bound_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo) == eph.pkix_pubkey
    )
    with pytest.raises(Exception):
        other = ke._generate("llm.kubetee.ai")
        other_key = load_der_public_key(other.pkix_pubkey)
        other_key.verify(sig, rd, ec.ECDSA(hashes.SHA256()))
