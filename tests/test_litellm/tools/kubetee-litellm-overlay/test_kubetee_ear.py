"""Pinned tests for the boot-time EAR mint (kubetee_ear) — 2026-10-27 fix.

Two root causes are pinned here so they cannot silently regress:

1. ``tee_pubkey_of`` was EC-only and raised ``AttributeError`` on the real
   (RSA) east-west identity key, so the RCAR mint could never bind the
   authorization key.
2. ``bootstrap_ear()`` had no caller at all, so ``/run/kubetee-eastwest/
   boot-ear.jwt`` was never written and the v1 bundle's ``appraisal`` block
   was permanently absent. The wiring lives in ``kubetee_eastwest.
   fetch_eastwest()`` (additive, best-effort).

Vectors are byte-for-byte on purpose: the RCAR runtime-data map is the
KBS/AS binding input (trustee backend.rs), so a mismatch here means the mint
would quote the wrong bytes.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib.util
import sys
from pathlib import Path
from typing import Any, Final

import pytest

_OVERLAY_DIR: Final = (
    Path(__file__).resolve().parents[4] / "tools" / "kubetee-litellm-overlay"
)


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _OVERLAY_DIR / f"{name}.py")
    assert spec is not None and spec.loader is not None, f"cannot load {name}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


kb: Final = _load("kubetee_binding")  # kubetee_ear imports `from kubetee_binding import jcs`
ke: Final = _load("kubetee_ear")

# --- fixed keys (deterministic JWK vectors) -------------------------------

P256_PEM: Final = b"""-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgGEuMvLr692JPquVD
hJos+zsLjlvEkk5bYPsXyD/p5IShRANCAATLGzr5JfYep08CB+2PuQdveiztXvWk
V2QjathhYFIYrAumGAlIWs6F2y/TfFmDNBdrRJloZ/NfKd7NzNZZgaZ7
-----END PRIVATE KEY-----"""

RSA_PEM: Final = b"""-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDLo/augTWKOKP9
7uKwh8cxyz7uIdxOAHKUU8S0CNYxzo8xlwVb6k1r//MoUNgPhWdG25SRq78UXd4G
lde5TqOI9cnhGmECnQXnk7bDzxtv9vIzWZDguZbiuHcq4TL9Xh3BhtjPzWWYH+u9
oKOOk9JcEbv38hpQizdYlPRHxIP6sY8qIX+C0jHJq8Cyq+RoE45pgqt4kw5Hei++
6/TI6pRNxKaGjZONb+kDYRVEkjKAfy2W/bA26Zx4XgZFz7FDjeq9bbx2qvhoO/RH
2YU0N0h4bf++F5tXEz/fYuWBzeX4V/o4we5hOxDYMC9Puw20ZLOomV/OWvL0m8QC
45K/A/SDAgMBAAECggEAY2qx1LHZ7JgIX8FPRHWVJtcd6u32+tG3Hnji8C3cPEam
m8Qp5py1nYNAN694O+OZ7vrmRlO9nnjRGw/uWFZu+j9chpv1PmxgZJU1xdSHhZre
1XjlhQC2DAuYigOVfCKFjmSB1rlk3ua+lT4me0Xpje9OgBbfB/FfXMyjkaH7+Nf1
M4Jdw4hYI100w9Crzh3JuSB/dkXvccUAvitzpvSK/b1yIa78BrLDGj5YRUeAUkaM
7zLtHYda3nu64ZgcAAUBfeGps9Nvdfqt+QNEClJ3soX0CIAhKryaXMAxSgfJmZI4
xpz+RIcj9QD3E+x4t3Ze36gGTKN6s5/2HEpkiCwmYQKBgQDzXTcv3Ua5mFdRvEyk
GT1bplcmBH6u4dJVr9hL5AiylzMdzZ+53Q6xBzivf8XtXd0vPfgTyh/uu49LnEUN
Vr+0Txbm6ZJU9ha757g/vdrkWETzDMJmffHHnTn/wwmSbR9Ps79bAYKfP2daPXh1
XXpiRMgOyHp2KGN22VaESW54EQKBgQDWNr5HLqEdkqd+TwGlyh1/q8vs96o69jXv
E6jy0HpEFAkdIOeIHFu7PtYuOiFNc0tezgiHawQJXoAAfp1sKcyLVUtGlLZbV+JY
nXEPM3+WpUWeGpJtOd4hZN9r8LvtkKXK2I+bTpYnjVXYfyszydAD36NHFIFFF5o2
/zA4KlGXUwKBgQCnfQ/uMSvrr5zo898LUROZb/GqiI1nbqODtXH3SQlzX/weFtZG
5Iyn6YBpyFY/9smzKcMCW6l+dDc6omIjvABT59qrMTU0o+khiWiU9eUgIl/RpoZk
Y2lzKBIyo9iCnfdesyaPS4rKbqiCwquUmrEP0KafBfrCNym9MfcJNECDAQKBgDl/
ci17F6XvcmPV4xRUHvzg6RjPFXNEGQ/2D/g0+0yAsD2QUnVXX0vwPt8jnULDuqxU
0zc+A1RceDEpyyl4Qr33hAAK9LOp8Ehm4iz5XrrZ28jnSvxkdvoxsEKx2E+Y7td2
r305Z9Zv+mXlJHx/JAWWJqZym4wnHK68an345fOfAoGBAN3igJrjKURex+drVipR
WMAr9HflxwP1Tnmp+K0n5BGaVFMo+Zcm2oZ5QY4AkYfqa9NqnpvaJc1YlqqV9ZG1
YRr/Shskj0ujBLk9lyo7N6GwqNHM3gZzl7lfCVzmxdha6XKAZpgpvc0OmI/oIlqx
zwisK9fsFxX0sSAc5lYmrxAv
-----END PRIVATE KEY-----"""

EC_JWK: Final[dict[str, str]] = {
    "kty": "EC",
    "crv": "P-256",
    "alg": "ES256",
    "x": "yxs6-SX2HqdPAgftj7kHb3os7V71pFdkI2rYYWBSGKw",
    "y": "C6YYCUhazoXbL9N8WYM0F2tEmWhn818p3s3M1lmBpns",
}
RSA_JWK: Final[dict[str, str]] = {
    "kty": "RSA",
    "alg": "RS256",
    "n": (
        "y6P2roE1ijij_e7isIfHMcs-7iHcTgBylFPEtAjWMc6PMZcFW-pNa__zKFDYD4VnRtuU"
        "kau_FF3eBpXXuU6jiPXJ4RphAp0F55O2w88bb_byM1mQ4LmW4rh3KuEy_V4dwYbYz81l"
        "mB_rvaCjjpPSXBG79_IaUIs3WJT0R8SD-rGPKiF_gtIxyavAsqvkaBOOaYKreJMOR3ov"
        "vuv0yOqUTcSmho2TjW_pA2EVRJIygH8tlv2wNumceF4GRc-xQ43qvW28dqr4aDv0R9mF"
        "NDdIeG3_vhebVxM_32Llgc3l-Ff6OMHuYTsQ2DAvT7sNtGSzqJlfzlry9JvEAuOSvwP0gw"
    ),
    "e": "AQAB",
}

VECTOR_NONCE: Final = "0123456789abcdef" * 4
VECTOR_RC_JCS: Final = (
    '{"additional-evidence":"","nonce":"0123456789abcdef0123456789abcdef'
    "0123456789abcdef0123456789abcdef\","
    '"tee-pubkey":{"alg":"ES256","crv":"P-256","kty":"EC",'
    '"x":"yxs6-SX2HqdPAgftj7kHb3os7V71pFdkI2rYYWBSGKw",'
    '"y":"C6YYCUhazoXbL9N8WYM0F2tEmWhn818p3s3M1lmBpns"}}'
)
VECTOR_RC_REPORT_DATA_HEX: Final = (
    "cf82398c59a016e3077a9e60d7257022b42b6b5918af46413ad7e8df92d2376d"
    "b585ff5220d1f16089522fed38e71d3e"
    + "00" * 16
)


def _load_key(pem: bytes):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    return load_pem_private_key(pem, password=None)


# --- tee_pubkey_of: both kbs-types arms ------------------------------------


def test_tee_pubkey_of_ec_p256():
    assert ke.tee_pubkey_of(_load_key(P256_PEM)) == EC_JWK


def test_tee_pubkey_of_rsa():
    # THE regression: the live east-west key is RSA (gen-certs.sh: genrsa).
    # Before the fix this raised AttributeError on RSAPublicNumbers.x.
    assert ke.tee_pubkey_of(_load_key(RSA_PEM)) == RSA_JWK


def test_tee_pubkey_of_rejects_non_p256_ec():
    from cryptography.hazmat.primitives.asymmetric import ec

    with pytest.raises(ke.EarError):
        ke.tee_pubkey_of(ec.generate_private_key(ec.SECP384R1()))


def test_tee_pubkey_from_key_pem_parses_and_never_raises():
    assert ke.tee_pubkey_from_key_pem(RSA_PEM) == RSA_JWK
    assert ke.tee_pubkey_from_key_pem(P256_PEM) == EC_JWK
    assert ke.tee_pubkey_from_key_pem(b"not a key") is None


# --- RCAR runtime-data binding (the bytes KBS hashes) ----------------------


def test_rcar_runtime_data_json_shape():
    data = ke.rcar_runtime_data_json(VECTOR_NONCE, EC_JWK)
    assert data == {
        "additional-evidence": "",
        "nonce": VECTOR_NONCE,
        "tee-pubkey": EC_JWK,
    }
    assert kb.jcs(data) == VECTOR_RC_JCS


def test_rcar_report_data_is_sha384_zero_padded():
    data = ke.rcar_runtime_data_json(VECTOR_NONCE, EC_JWK)
    rd = ke.rcar_report_data(data)
    assert len(rd) == 64
    assert rd == bytes.fromhex(VECTOR_RC_REPORT_DATA_HEX)
    # construction: SHA-384 (48 bytes) || 16 zero bytes (AS regularize_data)
    assert rd[48:] == b"\x00" * 16
    assert rd[:48] == hashlib.sha384(VECTOR_RC_JCS.encode()).digest()


# --- bootstrap_ear: cache write / best-effort semantics ---------------------


def test_bootstrap_ear_caches_token(tmp_path, monkeypatch):
    cache = tmp_path / "run" / "kubetee-eastwest" / "boot-ear.jwt"
    monkeypatch.setattr(ke, "EAR_CACHE_PATH", str(cache))

    async def fake_mint(tee_pubkey):
        assert tee_pubkey == RSA_JWK
        return ke.BootEar(token="ear.token.value", report_data=b"\x01" * 64)

    monkeypatch.setattr(ke, "mint_boot_ear", fake_mint)
    token = asyncio.run(ke.bootstrap_ear(RSA_JWK))
    assert token == "ear.token.value"
    assert cache.read_text() == "ear.token.value"
    assert ke.load_cached_ear() == "ear.token.value"


def test_bootstrap_ear_is_best_effort(tmp_path, monkeypatch):
    monkeypatch.setattr(ke, "EAR_CACHE_PATH", str(tmp_path / "boot-ear.jwt"))

    async def boom(tee_pubkey):
        raise RuntimeError("Trustee down")

    monkeypatch.setattr(ke, "mint_boot_ear", boom)
    assert asyncio.run(ke.bootstrap_ear(EC_JWK)) is None
    assert ke.load_cached_ear() is None


def test_load_cached_ear_absent(tmp_path, monkeypatch):
    monkeypatch.setattr(ke, "EAR_CACHE_PATH", str(tmp_path / "missing.jwt"))
    assert ke.load_cached_ear() is None
