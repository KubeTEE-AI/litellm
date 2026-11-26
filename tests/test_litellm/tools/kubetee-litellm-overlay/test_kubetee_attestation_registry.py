"""CI-enforced gates for the SIGNED reference-registry matcher + path fix.

These are the security-critical behaviors of ``kubetee_attestation`` that the
measured-release gate must never let regress:

  * ``any-active-record`` matching (a live register pair approves iff it matches
    some *active*, *unexpired* record).
  * expired / deprecated / revoked record REJECTION (the 90-day lifecycle).
  * tampered-registry SIGNATURE rejection (Ed25519 over RFC 8785 JCS of the
    document minus the ``signature`` block).
  * ROLE gating (a record for a different role cannot approve this backend).
  * ``_backend_attest_url`` ``/v1`` path fix (the backend evidence route is at
    the root of its strict-mTLS listener, not under ``/v1``).

The rich, standalone runners live beside the overlay in
``tools/kubetee-litellm-overlay/tests/{test_registry_matcher,test_breaker}.py``;
this file pins the same gates in the pytest suite CI actually collects so a
measured release cannot ship a regression unnoticed. Network-free; no cluster,
no Trustee.
"""

from __future__ import annotations

import base64
import importlib.util
import sys
import types
from pathlib import Path
from typing import Any, Final

import pytest

_OVERLAY_DIR: Final = (
    Path(__file__).resolve().parents[4] / "tools" / "kubetee-litellm-overlay"
)


def _ensure_litellm() -> None:
    """Register minimal ``litellm`` stubs only when the real package is absent.

    Under CI the packaged ``litellm`` is importable and wins. The standalone
    runner needs the stub because it is executed with a bare interpreter; we
    mirror that safety net here so the gate is runnable either way.
    """
    try:  # pragma: no cover - trivial import probe
        import litellm.integrations.custom_logger  # noqa: F401

        return
    except Exception:
        pass

    litellm_mod = types.ModuleType("litellm")
    integrations = types.ModuleType("litellm.integrations")
    custom_logger = types.ModuleType("litellm.integrations.custom_logger")

    class CustomLogger:  # noqa: D401 - stub base class
        pass

    custom_logger.CustomLogger = CustomLogger
    logging_mod = types.ModuleType("litellm._logging")

    class _L:
        def error(self, *a: Any, **k: Any) -> None:
            pass

        def info(self, *a: Any, **k: Any) -> None:
            pass

    logging_mod.verbose_proxy_logger = _L()
    sys.modules["litellm"] = litellm_mod
    sys.modules["litellm.integrations"] = integrations
    sys.modules["litellm.integrations.custom_logger"] = custom_logger
    sys.modules["litellm._logging"] = logging_mod


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _OVERLAY_DIR / f"{name}.py")
    assert spec is not None and spec.loader is not None, f"cannot load {name}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_ensure_litellm()
sys.path.insert(0, str(_OVERLAY_DIR))  # intra-overlay imports (kubetee_binding, ...)
ka: Final = _load("kubetee_attestation")

_CFG: Final = (
    "0484a58e5927efd31bf871c74bcc9f1768f4335bb92340176989b3c5b320f934"
    "1d772b9e3e9c4fe4d824613cc19e6e0b"
)
_GOOD: Final = {
    "mrtd": "aa" * 48,
    "mrconfigid": _CFG,
    "rtmr0": "11" * 48,
    "rtmr1": "22" * 48,
    "rtmr2": "33" * 48,
    "rtmr3": "44" * 48,
}


def _record(
    rec_id: str,
    *,
    status: str = "active",
    valid_until: str = "2099-01-01T00:00:00Z",
    role: str = "image-gen",
    meas: dict | None = None,
) -> dict:
    return {
        "id": rec_id,
        "model": "xiaomi/mimo-v2.6-pro",
        "role": role,
        "status": status,
        "valid_until": valid_until,
        "measurements": dict(meas or _GOOD),
    }


def _registry(records: list[dict]) -> dict:
    return {"schema": "kubetee.tee-measurements-registry/1", "records": records}


def test_any_active_record_match() -> None:
    ok, rid = ka._match_registry_record(dict(_GOOD), [_record("mimo-1")])
    assert ok and rid == "mimo-1"


def test_any_active_record_matches_second() -> None:
    drifted = dict(_GOOD, rtmr2="ee" * 48)
    rec_a = _record("A")
    rec_b = _record("B", meas=dict(_GOOD, rtmr2="ee" * 48))
    ok, rid = ka._match_registry_record(drifted, [rec_a, rec_b])
    assert ok and rid == "B"


def test_undeclared_register_cannot_trip() -> None:
    partial = _record("partial", meas={"mrtd": "aa" * 48})
    ok, rid = ka._match_registry_record(dict(_GOOD, rtmr0="zz" * 48), [partial])
    assert ok and rid == "partial"


def test_no_matching_record_rejected() -> None:
    ok, reason = ka._match_registry_record(dict(_GOOD, rtmr2="ee" * 48), [_record("A")])
    assert not ok and "registry-no-match" in reason


def test_expired_record_rejected() -> None:
    expired = _record("old", valid_until="2020-01-01T00:00:00Z")
    ok, reason = ka._match_registry_record(dict(_GOOD), [expired])
    assert not ok and "no-active-record" in reason


@pytest.mark.parametrize("status", ["deprecated", "revoked", "retired"])
def test_non_active_status_rejected(status: str) -> None:
    ok, reason = ka._match_registry_record(dict(_GOOD), [_record(f"dep-{status}", status=status)])
    assert not ok and "no-active-record" in reason


def test_expired_cannot_rescue_non_matching_active() -> None:
    expired = _record("old", valid_until="2020-01-01T00:00:00Z")
    ok, reason = ka._match_registry_record(
        dict(_GOOD), [expired, _record("A", meas=dict(_GOOD, rtmr2="ee" * 48))]
    )
    assert not ok and "registry-no-match" in reason


def test_signature_verify_and_tamper_reject() -> None:
    ed25519 = pytest.importorskip(
        "cryptography.hazmat.primitives.asymmetric.ed25519"
    )
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()

    def signed(records: list[dict]) -> dict:
        reg = _registry(records)
        sig = priv.sign(ka._jcs({k: v for k, v in reg.items() if k != "signature"}))
        reg["signature"] = {"alg": "ed25519", "sig": base64.b64encode(sig).decode("ascii")}
        return reg

    saved_key = ka._REGISTRY_PUBLIC_KEY_B64
    try:
        ka._REGISTRY_PUBLIC_KEY_B64 = base64.b64encode(pub).decode("ascii")
        good = signed([_record("mimo-1")])
        assert ka._verify_registry_signature(good)

        tampered = signed([_record("mimo-1")])
        tampered["records"][0]["measurements"]["mrtd"] = "ee" * 48
        assert not ka._verify_registry_signature(tampered)

        other = ed25519.Ed25519PrivateKey.generate()
        ka._REGISTRY_PUBLIC_KEY_B64 = base64.b64encode(
            other.public_key().public_bytes_raw()
        ).decode("ascii")
        assert not ka._verify_registry_signature(good)
    finally:
        ka._REGISTRY_PUBLIC_KEY_B64 = saved_key


def test_wrong_role_trips_verifier() -> None:
    trips, _ = ka._verify_backend_evidence(
        {
            "tee": "tdx",
            "role": "llm-gen",
            "claims": {
                "quote": {
                    "body": {
                        "mr_td": _GOOD["mrtd"],
                        "mr_config_id": _CFG,
                        "rtmr_0": _GOOD["rtmr0"],
                        "rtmr_1": _GOOD["rtmr1"],
                        "rtmr_2": _GOOD["rtmr2"],
                        "rtmr_3": _GOOD["rtmr3"],
                    }
                }
            },
        }
    )
    assert any("role-mismatch" in t for t in trips)


def test_registry_match_keeps_breaker_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _reg():
        return _registry([_record("mimo-1")])

    monkeypatch.setattr(ka, "_load_registry", _reg)
    dummy_quote = base64.b64encode(b"\x00" * 48 + b"\x11" * 584).decode("ascii")
    ev = {
        "tee": "tdx",
        "role": "image-gen",
        "quote": dummy_quote,
        "claims": {
            "quote": {
                "body": {
                    "mr_td": _GOOD["mrtd"],
                    "mr_config_id": _CFG,
                    "rtmr_0": _GOOD["rtmr0"],
                    "rtmr_1": _GOOD["rtmr1"],
                    "rtmr_2": _GOOD["rtmr2"],
                    "rtmr_3": _GOOD["rtmr3"],
                }
            }
        },
        "epoch": {"id": "e", "valid_until": "2099-01-01T00:05:00Z"},
    }

    import asyncio

    ka._breakers.clear()
    asyncio.run(ka._observe_backend_evidence("ep-reg", ev))
    assert not ka.breaker_state("ep-reg")["open"]


def test_backend_attest_url_strips_v1() -> None:
    assert (
        ka._backend_attest_url("https://mimo-svc.nemo.svc.cluster.local:8443/v1")
        == "https://mimo-svc.nemo.svc.cluster.local:8443/kubetee/evidence"
    )
    assert (
        ka._backend_attest_url("https://mimo-svc.nemo.svc.cluster.local:8443")
        == "https://mimo-svc.nemo.svc.cluster.local:8443/kubetee/evidence"
    )
    assert (
        ka._backend_attest_url("https://mimo-svc:8443/v1/")
        == "https://mimo-svc:8443/kubetee/evidence"
    )
