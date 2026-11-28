"""Native CoCo v0.23 fixture shared with the gm-miner SNP verifier.

The fixture is stock attestation-service/tests/e2e/evidence.json, not a
KubeTEE live-release acceptance measurement. Rust verifies its AMD chain and
launch measurement; these tests check the producer's protocol and binding.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("cryptography.hazmat.primitives.serialization")
OVERLAY = Path(__file__).resolve().parents[4] / "tools" / "kubetee-litellm-overlay"
FIXTURE = Path(__file__).with_name("fixtures") / "kubetee" / "snp-evidence.json"
ROUTES = {}

# This protocol fixture replaces LiteLLM modules; it must run in isolation.
pytestmark = pytest.mark.kubetee_isolated_protocol_fixture


def load():
    for name in ("kubetee_binding", "kubetee_ear", "kubetee_proof", "kubetee_ephemeral"):
        spec = importlib.util.spec_from_file_location(name, OVERLAY / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)

    class App:
        routes = []

        def add_api_route(self, path, endpoint, **kwargs):
            ROUTES[path] = endpoint
            self.routes.append(SimpleNamespace(path=path))

    class JSONResponse:
        def __init__(self, content, status_code=200):
            self.body = json.dumps(content).encode()
            self.status_code = status_code

    sys.modules["litellm"] = SimpleNamespace()
    proxy = SimpleNamespace(app=App())
    sys.modules["litellm.proxy"] = proxy
    sys.modules["litellm.proxy.proxy_server"] = proxy
    logger = SimpleNamespace(CustomLogger=type("CustomLogger", (), {}))
    sys.modules["litellm.integrations"] = logger
    sys.modules["litellm.integrations.custom_logger"] = logger
    class _StubHTTPException(Exception):
        # A faithful fastapi.HTTPException stand-in: it must accept the
        # (status_code=..., detail=..., headers=...) call shape (the 429 raise
        # uses it), so RuntimeError cannot be used as the stub here.
        def __init__(self, status_code: int = 500, detail=None, headers=None):
            super().__init__(status_code, detail)
            self.status_code = status_code
            self.detail = detail
            self.headers = headers

    sys.modules["fastapi"] = SimpleNamespace(HTTPException=_StubHTTPException, Query=lambda default: default)
    sys.modules["fastapi.responses"] = SimpleNamespace(JSONResponse=JSONResponse)
    spec = importlib.util.spec_from_file_location("kubetee_attestation", OVERLAY / "kubetee_attestation.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def gateway(monkeypatch, tmp_path):
    monkeypatch.setenv("KUBETEE_TEE", "snp")
    module = load()
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "llm.kubetee.ai")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(12345)
        .not_valid_before(__import__("datetime").datetime(2026, 1, 1, tzinfo=__import__("datetime").timezone.utc))
        .not_valid_after(__import__("datetime").datetime(2028, 1, 1, tzinfo=__import__("datetime").timezone.utc))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("llm.kubetee.ai")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    (tmp_path / "tls.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (tmp_path / "tls.crt").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    monkeypatch.setattr(module, "_TLS_CERT_PATH", str(tmp_path / "tls.crt"))
    monkeypatch.setattr(module, "_TLS_KEY_PATH", str(tmp_path / "tls.key"))
    return module


@pytest.fixture
def evidence(gateway, monkeypatch):
    document = json.loads(FIXTURE.read_text())
    async def request(runtime_data, *args, **kwargs):
        supplied = json.loads(json.dumps(document))
        supplied["attestation_report"]["report_data"] = list(base64.urlsafe_b64decode(runtime_data + "=" * (-len(runtime_data) % 4)))
        return supplied
    monkeypatch.setattr(gateway, "_aa_get_evidence", request)
    return document


def test_stock_coco_json_and_gm_miner_binding_are_preserved(gateway, evidence):
    response = json.loads(asyncio.run(ROUTES["/v1/attestation"]("11" * 32)).body)
    assert response["evidence"]["snp"]["schema"] == "kubetee.snp-evidence/1"
    # Native CoCo chain is preserved as a prefix (ARK/ASK may be appended).
    native = evidence["cert_chain"]
    served = response["evidence"]["snp"]["cert_chain"]
    assert served[: len(native)] == native
    report = response["evidence"]["snp"]["attestation_report"]
    for field in ("measurement", "host_data", "signature", "current_tcb", "version"):
        assert report[field] == evidence["attestation_report"][field]
    statement = response["bindings"]["report_data_statement"]
    assert response["bindings"]["version"] == "kubetee.attestation.v2"
    # v2: the report_data is SHA-384(framed(pkix, nonce, context)) || 16 zeros,
    # re-derived from the served statement fields (not a hash of the statement).
    expected_rd = gateway._report_data_from_payload(response, "11" * 32)
    assert len(expected_rd) == 64
    assert bytes(response["evidence"]["snp"]["attestation_report"]["report_data"]) == expected_rd
    assert response["quote"] is None and response["cc_eventlog"] is None
    assert response["runtime_class"] == "kata-qemu-snp-runtime-rs"
    # v2 possession: an ECDSA P-256 signature over the quote-bound report_data.
    assert response["key_possession"]["alg"] == "ecdsa-secp256r1-sha256"
    assert response["key_possession"]["input"] == "quote_report_data"
    assert "tls_possession" not in response  # legacy serving-key proof is retired
    assert response["keyset"]["tls_public_keys"]


@pytest.mark.parametrize("legacy", ["sev", "sev-es"])
def test_legacy_sev_is_never_an_snp_fallback(monkeypatch, legacy):
    monkeypatch.setenv("KUBETEE_TEE", legacy)
    with pytest.raises(Exception, match="unsupported KUBETEE_TEE"):
        load()


def test_an_empty_certificate_is_rejected(gateway, monkeypatch):
    document = json.loads(FIXTURE.read_text())
    document["cert_chain"] = [{"cert_type": "VCEK", "data": []}]
    async def request(*args, **kwargs):
        return document
    monkeypatch.setattr(gateway, "_aa_get_evidence", request)
    with pytest.raises(gateway.EvidenceError):
        asyncio.run(gateway.get_attestation_payload("11" * 32))


def test_inline_uses_native_snp_headers(gateway, evidence):
    headers = asyncio.run(
        gateway.kubetee_attestation_logger.async_post_call_response_headers_hook(
            data={"model": "amd-test"}, user_api_key_dict=SimpleNamespace(),
            response=SimpleNamespace(), request_headers={"x-kubetee-nonce": "22" * 32},
            litellm_call_info={},
        )
    )
    assert "X-KubeTEE-Attestation-SNP" in headers
    assert "X-KubeTEE-Attestation-Quote" not in headers
    encoded = headers["X-KubeTEE-Attestation-SNP"]
    assert json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))["schema"] == "kubetee.snp-evidence/1"
    assert headers["X-KubeTEE-Attestation-Tee"] == "snp"
    assert headers["X-KubeTEE-Runtime-Class"] == "kata-qemu-snp-runtime-rs"
    assert headers["X-KubeTEE-Nonce"] == "22" * 32


def test_tdx_path_still_does_not_accept_an_amd_report(gateway):
    with pytest.raises(gateway.EvidenceError):
        gateway._hardware_evidence(json.loads(FIXTURE.read_text()), bytes(64))
    gateway.TEE_TYPE = "tdx"
    with pytest.raises(gateway.EvidenceError):
        gateway._hardware_evidence(json.loads(FIXTURE.read_text()), bytes(64))


# --- Phase 1: raw_report + full cert chain (envelope-raw-report) ------------
# Golden = the exact 1184-byte AMD report for the ORIGINAL fixture, produced by
# the Rust `sev` 9.0.0 oracle (kubetee-attestation-verifier `snp-report-bytes`).
# The Python encoder MUST be byte-identical to it (the VCEK signs the first
# 0x2A0 bytes). Note the served evidence rewrites report_data to the nonce
# binding, so the absolute-golden check runs the encoder on the UNMUTATED
# fixture report directly.
_GOLDEN_RAW_SHA256 = "18e907bf99a957d8ccf30f2081da17f673da648a7a0b9d551a866e875234c21a"


def test_raw_report_encoder_is_byte_exact_vs_rust_oracle(gateway, evidence):
    # Unmutated fixture -> absolute 1184-byte golden from the Rust sev oracle.
    raw = gateway._snp_raw_report(evidence["attestation_report"])
    assert len(raw) == 1184
    assert hashlib.sha256(raw).hexdigest() == _GOLDEN_RAW_SHA256


def test_raw_report_present_and_self_consistent(gateway, evidence):
    response = json.loads(asyncio.run(ROUTES["/v1/attestation"]("33" * 32)).body)
    snp = response["evidence"]["snp"]
    raw = base64.b64decode(snp["raw_report"])
    assert snp["raw_report_len"] == 1184
    assert len(raw) == 1184
    assert snp["raw_report_sha256"] == hashlib.sha256(raw).hexdigest()
    # The signed body's report_data equals the served binding (report rewrites it).
    expected_rd = gateway._report_data_from_payload(response, "33" * 32)
    assert raw[0x050:0x050 + 64] == expected_rd


def test_raw_report_fields_sit_at_amd_offsets(gateway, evidence):
    report = evidence["attestation_report"]
    response = json.loads(asyncio.run(ROUTES["/v1/attestation"]("44" * 32)).body)
    raw = base64.b64decode(response["evidence"]["snp"]["raw_report"])
    # Signed body is 0..0x2A0 (672 B); signature block is r@0x2A0 || s@0x2E8.
    assert raw[0x090:0x090 + 48] == bytes(report["measurement"])
    assert raw[0x0C0:0x0C0 + 32] == bytes(report["host_data"])
    assert raw[0x140:0x140 + 32] == bytes(report["report_id"])
    assert raw[0x1A0:0x1A0 + 64] == bytes(report["chip_id"])
    assert raw[0x2A0:0x2A0 + 72] == bytes(report["signature"]["r"])
    assert raw[0x2E8:0x2E8 + 72] == bytes(report["signature"]["s"])
    # The 512-byte signature block tail and pre-signature reserved are MBZ.
    assert raw[0x330:0x4A0] == bytes(0x4A0 - 0x330)


def test_cert_chain_augmented_with_ark_ask(gateway, evidence):
    # Pre-seed a cached ARK/ASK (no network in tests) and confirm the gateway
    # completes a VCEK-only chain while preserving CoCo's VCEK first.
    gateway._KDS_CHAIN_CACHE["Genoa"] = [
        {"cert_type": "ASK", "data": [1, 2, 3]},
        {"cert_type": "ARK", "data": [4, 5, 6]},
    ]
    response = json.loads(asyncio.run(ROUTES["/v1/attestation"]("55" * 32)).body)
    chain = response["evidence"]["snp"]["cert_chain"]
    types = [e["cert_type"] for e in chain]
    assert types[0] == "VCEK"          # CoCo's VCEK is preserved first
    assert "ASK" in types and "ARK" in types
