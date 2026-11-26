"""CI-enforced gates for SNP cert-chain delivery (VCEK + ASK/ARK via AMD KDS).

Root cause this pins: CoCo's AA returns an EMPTY ``cert_chain`` on our guests
(the firmware cert page is empty at boot and the guest does no KDS fetch), so a
verifier gets no key to check the report signature. ``_snp_cert_chain_augment``
now completes the chain to leaf-to-root ``VCEK -> ASK -> ARK`` by fetching the
exact signing VCEK (this report's chip + reported TCB) and the static ASK/ARK
from AMD KDS. These tests are network-free (``_kds_get`` is stubbed) and gate
the delivery + fail-safe behavior so a measured release cannot regress it:

  * empty CoCo chain  -> fetch VCEK + ASK + ARK (leaf-to-root order)
  * CoCo VCEK present -> append only the missing ASK + ARK (no VCEK refetch)
  * already complete  -> unchanged, no KDS call
  * KDS unreachable   -> ORIGINAL chain unchanged (fail-safe, no invented cert)
  * VCEK fetch fails  -> ORIGINAL chain unchanged, NOT a bare ASK/ARK
  * no double-append  -> a complete chain is never duplicated

The rich standalone runner lives beside the overlay in
``tools/kubetee-litellm-overlay/tests/test_snp_cert_chain.py``; this file pins
the same gates in the pytest suite CI actually collects. Network-free; no
cluster, no Trustee, no secret material (AMD KDS serves public certificates).
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

    Under CI the packaged ``litellm`` is importable and wins; the standalone
    runner needs the stub. Mirrors ``test_kubetee_attestation_registry``.
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

# Distinct non-empty dummy DER blobs: delivery/ordering/fail-safe are under
# test, not X.509 cryptography (that is covered by the Rust reference verifier).
_VCEK_DER: Final = b"\x30\x82\x01\x00VCEK-leaf"
_ASK_DER: Final = b"\x30\x82\x01\x00ASK-intermediate"
_ARK_DER: Final = b"\x30\x82\x01\x00ARK-root"


def _pem(der: bytes) -> str:
    b = base64.b64encode(der).decode()
    return f"-----BEGIN CERTIFICATE-----\n{b}\n-----END CERTIFICATE-----\n"


_CA_PEM: Final = _pem(_ASK_DER) + _pem(_ARK_DER)  # KDS order: [ASK, ARK]
_VCEK_PEM: Final = _pem(_VCEK_DER)


def _report() -> dict[str, Any]:
    return {
        "cpuid_fam_id": 0x19,  # genoa
        "cpuid_mod_id": 0x11,
        "chip_id": list(range(64)),
        "reported_tcb": {"bootloader": 12, "tee": 0, "snp": 28, "microcode": 88},
    }


def _install_kds(monkeypatch, *, vcek_ok: bool = True, ca_ok: bool = True) -> list[str]:
    """Monkeypatch ``_kds_get``; record the URLs fetched. Returns the call log."""
    calls: list[str] = []

    def fake(url: str) -> bytes:
        calls.append(url)
        if "cert_chain" in url:
            if not ca_ok:
                raise OSError("kds ca unreachable")
            return _CA_PEM.encode()
        if not vcek_ok:
            raise OSError("kds vcek unreachable")
        return _VCEK_PEM.encode()

    monkeypatch.setattr(ka, "_kds_get", fake)
    return calls


def _reset() -> None:
    ka._KDS_CHAIN_CACHE.clear()
    ka._KDS_VCEK_CACHE.clear()


def test_empty_chain_fetches_full_vcek_ask_ark(monkeypatch) -> None:
    _reset()
    calls = _install_kds(monkeypatch)
    out = ka._snp_cert_chain_augment(_report(), [])
    assert [e["cert_type"] for e in out] == ["VCEK", "ASK", "ARK"]  # leaf-to-root
    assert out[0]["data"] == list(_VCEK_DER)
    assert out[1]["data"] == list(_ASK_DER)
    assert out[2]["data"] == list(_ARK_DER)
    assert any("cert_chain" in u for u in calls) and any(
        "cert_chain" not in u for u in calls
    ), calls


def test_coco_vcek_gets_only_missing_ca(monkeypatch) -> None:
    _reset()
    calls = _install_kds(monkeypatch)
    coco = [{"cert_type": "VCEK", "data": list(_VCEK_DER)}]
    out = ka._snp_cert_chain_augment(_report(), coco)
    assert [e["cert_type"] for e in out] == ["VCEK", "ASK", "ARK"]
    # The VCEK leaf is CoCo's, NOT re-fetched: only the CA URL was hit.
    assert all("cert_chain" in u for u in calls), calls
    assert out[0]["data"] == list(_VCEK_DER)


def test_complete_chain_unchanged_no_kds_call(monkeypatch) -> None:
    _reset()
    calls = _install_kds(monkeypatch)
    complete = [
        {"cert_type": "VCEK", "data": list(_VCEK_DER)},
        {"cert_type": "ASK", "data": list(_ASK_DER)},
        {"cert_type": "ARK", "data": list(_ARK_DER)},
    ]
    out = ka._snp_cert_chain_augment(_report(), complete)
    assert out == complete
    assert calls == [], calls


def test_kds_unreachable_leaves_original_chain(monkeypatch) -> None:
    _reset()
    _install_kds(monkeypatch, vcek_ok=False, ca_ok=False)
    coco = [{"cert_type": "VCEK", "data": list(_VCEK_DER)}]
    out = ka._snp_cert_chain_augment(_report(), coco)
    assert out == coco  # unchanged, no invented certs


def test_vcek_fetch_fail_does_not_emit_bare_ca(monkeypatch) -> None:
    _reset()
    _install_kds(monkeypatch, vcek_ok=False, ca_ok=True)  # CA ok, VCEK NOT
    out = ka._snp_cert_chain_augment(_report(), [])
    assert out == []  # never a bare ASK/ARK with no VCEK anchor


def test_no_double_append(monkeypatch) -> None:
    _reset()
    _install_kds(monkeypatch)
    out1 = ka._snp_cert_chain_augment(_report(), [])
    out2 = ka._snp_cert_chain_augment(_report(), out1)  # already-augmented
    assert [e["cert_type"] for e in out2] == ["VCEK", "ASK", "ARK"]
    assert len(out2) == 3


def test_vcek_as_raw_der_is_parsed(monkeypatch) -> None:
    """REGRESSION: AMD's VCEK endpoint returns raw DER (0x30 ...), not PEM.

    A PEM-only parser decoded the DER body as ASCII and threw, so the fail-safe
    returned the ORIGINAL empty chain in production even though the code was
    'correct'. This test serves the VCEK as the raw bytes AMD actually returns
    and requires the chain to still complete to VCEK -> ASK -> ARK.
    """
    _reset()

    def fake(url: str) -> bytes:
        if "cert_chain" in url:
            return _CA_PEM.encode()  # CA endpoint: PEM bundle [ASK, ARK]
        return _VCEK_DER  # VCEK endpoint: RAW DER (starts 0x30)

    monkeypatch.setattr(ka, "_kds_get", fake)
    out = ka._snp_cert_chain_augment(_report(), [])
    assert [e["cert_type"] for e in out] == ["VCEK", "ASK", "ARK"]
    assert out[0]["data"] == list(_VCEK_DER)


def test_cert_ders_handles_pem_and_der() -> None:
    """Unit: ``_cert_ders`` accepts a PEM bundle, a raw DER cert, and junk."""
    # PEM bundle -> one DER per cert block
    assert ka._cert_ders(_CA_PEM.encode()) == [_ASK_DER, _ARK_DER]
    # raw DER (first byte 0x30) -> a single cert
    assert ka._cert_ders(_VCEK_DER) == [_VCEK_DER]
    # non-cert bytes -> empty (fail-safe, no crash)
    assert ka._cert_ders(b"") == []
    assert ka._cert_ders(b"\x00\x01\x02 not a cert") == []
