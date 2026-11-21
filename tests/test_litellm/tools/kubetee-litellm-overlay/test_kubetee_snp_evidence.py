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


def load():
    for name in ("kubetee_binding", "kubetee_ear"):
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
    sys.modules["fastapi"] = SimpleNamespace(HTTPException=RuntimeError, Query=lambda default: default)
    sys.modules["fastapi.responses"] = SimpleNamespace(JSONResponse=JSONResponse)
    spec = importlib.util.spec_from_file_location("kubetee_attestation", OVERLAY / "kubetee_attestation.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def gateway(monkeypatch, tmp_path):
    monkeypatch.setenv("KUBETEE_TEE", "snp")
    monkeypatch.setenv("KUBETEE_ATTESTATION_V1", "1")
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
    assert response["evidence"]["snp"]["cert_chain"] == evidence["cert_chain"]
    report = response["evidence"]["snp"]["attestation_report"]
    for field in ("measurement", "host_data", "signature", "current_tcb", "version"):
        assert report[field] == evidence["attestation_report"][field]
    statement = response["bindings"]["report_data_statement"]
    expected = hashlib.sha256(statement.encode()).digest()
    assert bytes(response["evidence"]["snp"]["attestation_report"]["report_data"]) == expected + bytes(32)
    assert response["quote"] is None and response["cc_eventlog"] is None
    assert response["runtime_class"] == "kata-qemu-snp-runtime-rs"
    assert response["tls_possession"]["tls_signature_alg"] == "ES256"
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
