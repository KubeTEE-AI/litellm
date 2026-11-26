#!/usr/bin/env python3
"""Offline regression for SNP cert-chain delivery (VCEK + ASK/ARK via KDS).

Run from anywhere; needs no cluster, no Trustee, NO network (AMD KDS is
stubbed). Stubs the `litellm` package and exercises `_snp_cert_chain_augment`
in kubetee_attestation, the fix for the empty ``cert_chain`` gap (CoCo's AA
returns no certs on our guests — the firmware cert page is empty and the guest
does no KDS fetch):

  * empty CoCo chain  -> gateway fetches VCEK + ASK + ARK (leaf-to-root order)
  * CoCo VCEK present -> gateway appends only the missing ASK + ARK
  * already complete  -> unchanged, no KDS call
  * KDS unreachable   -> ORIGINAL chain unchanged (fail-safe, no invented cert)
  * VCEK fetch fails  -> ORIGINAL chain unchanged, NOT a bare ASK/ARK (the
    unanchored-CA case: emitting ASK/ARK with no VCEK is worse than nothing)
  * no double-append  -> a cached/complete chain is never duplicated

Exit 0 = all pass. Mirrors test_breaker.py / test_registry_matcher.py.
"""
from __future__ import annotations

import os
import sys
import types


def _stub_litellm() -> None:
    if "litellm" in sys.modules:
        return
    litellm_mod = types.ModuleType("litellm")
    integrations = types.ModuleType("litellm.integrations")
    custom_logger = types.ModuleType("litellm.integrations.custom_logger")

    class CustomLogger:  # noqa: D401 - stub base class
        pass

    custom_logger.CustomLogger = CustomLogger
    logging_mod = types.ModuleType("litellm._logging")

    class _L:
        def error(self, *a, **k):
            pass

        def info(self, *a, **k):
            pass

    logging_mod.verbose_proxy_logger = _L()
    sys.modules["litellm"] = litellm_mod
    sys.modules["litellm.integrations"] = integrations
    sys.modules["litellm.integrations.custom_logger"] = custom_logger
    sys.modules["litellm._logging"] = logging_mod


_stub_litellm()
HERE = os.path.dirname(os.path.abspath(__file__))
OVERLAY = os.path.dirname(HERE)
sys.path.insert(0, OVERLAY)

import kubetee_attestation as ka  # noqa: E402

_results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    _results.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  {detail}" if not ok else ""))


def _pem(der: bytes) -> str:
    import base64
    b = base64.b64encode(der).decode()
    return f"-----BEGIN CERTIFICATE-----\n{b}\n-----END CERTIFICATE-----\n"


# Distinct non-empty dummy DER blobs (delivery logic, not crypto, is under test).
_VCEK_DER = b"\x30\x82\x01\x00VCEK-leaf"
_ASK_DER = b"\x30\x82\x01\x00ASK-intermediate"
_ARK_DER = b"\x30\x82\x01\x00ARK-root"
_CA_PEM = _pem(_ASK_DER) + _pem(_ARK_DER)  # KDS order: [ASK, ARK]
_VCEK_PEM = _pem(_VCEK_DER)


def _report() -> dict:
    return {
        "cpuid_fam_id": 0x19,  # genoa
        "cpuid_mod_id": 0x11,
        "chip_id": list(range(64)),
        "reported_tcb": {"bootloader": 12, "tee": 0, "snp": 28, "microcode": 88},
    }


def _install_kds(*, vcek_ok: bool = True, ca_ok: bool = True) -> list[str]:
    """Monkeypatch `_kds_get`; record the URLs fetched. Returns the call log."""
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

    ka._kds_get = fake  # type: ignore[assignment]
    return calls


def _reset() -> None:
    ka._KDS_CHAIN_CACHE.clear()
    ka._KDS_VCEK_CACHE.clear()


# ---------------------------------------------------------------------------


def test_empty_chain_fetches_full_vcek_ask_ark() -> None:
    _reset()
    calls = _install_kds()
    out = ka._snp_cert_chain_augment(_report(), [])
    types_ = [e["cert_type"] for e in out]
    assert types_ == ["VCEK", "ASK", "ARK"], types_  # leaf-to-root order
    assert out[0]["data"] == list(_VCEK_DER)
    assert out[1]["data"] == list(_ASK_DER)
    assert out[2]["data"] == list(_ARK_DER)
    assert any("cert_chain" in u for u in calls) and any("cert_chain" not in u for u in calls), calls


def test_coco_vcek_gets_only_missing_ca() -> None:
    _reset()
    calls = _install_kds()
    coco = [{"cert_type": "VCEK", "data": list(_VCEK_DER)}]
    out = ka._snp_cert_chain_augment(_report(), coco)
    types_ = [e["cert_type"] for e in out]
    assert types_ == ["VCEK", "ASK", "ARK"], types_
    # The VCEK leaf is CoCo's, NOT re-fetched: only the CA URL was hit.
    assert all("cert_chain" in u for u in calls), calls
    assert out[0]["data"] == list(_VCEK_DER)


def test_complete_chain_unchanged_no_kds_call() -> None:
    _reset()
    calls = _install_kds()
    complete = [
        {"cert_type": "VCEK", "data": list(_VCEK_DER)},
        {"cert_type": "ASK", "data": list(_ASK_DER)},
        {"cert_type": "ARK", "data": list(_ARK_DER)},
    ]
    out = ka._snp_cert_chain_augment(_report(), complete)
    assert out == complete
    assert calls == [], calls


def test_kds_unreachable_leaves_original_chain() -> None:
    _reset()
    _install_kds(vcek_ok=False, ca_ok=False)
    coco = [{"cert_type": "VCEK", "data": list(_VCEK_DER)}]
    out = ka._snp_cert_chain_augment(_report(), coco)
    assert out == coco, out  # unchanged, no invented certs


def test_vcek_fetch_fail_does_not_emit_bare_ca() -> None:
    _reset()
    _install_kds(vcek_ok=False, ca_ok=True)  # CA reachable, VCEK NOT
    out = ka._snp_cert_chain_augment(_report(), [])
    assert out == [], out  # never bare ASK/ARK with no VCEK anchor


def test_no_double_append() -> None:
    _reset()
    _install_kds()
    out1 = ka._snp_cert_chain_augment(_report(), [])
    # Run again passing the already-augmented chain: must not grow.
    out2 = ka._snp_cert_chain_augment(_report(), out1)
    assert [e["cert_type"] for e in out2] == ["VCEK", "ASK", "ARK"]
    assert len(out2) == 3, [e["cert_type"] for e in out2]


def test_vcek_as_raw_der_is_parsed() -> None:
    """REGRESSION: AMD's VCEK endpoint returns raw DER (0x30 ...), not PEM.

    A PEM-only parser decoded the DER body as ASCII and threw, so the fail-safe
    returned the ORIGINAL empty chain in production even though the code looked
    correct. Serve the VCEK as the raw bytes AMD actually returns and require
    the chain to still complete to VCEK -> ASK -> ARK.
    """
    _reset()

    def fake(url: str) -> bytes:
        if "cert_chain" in url:
            return _CA_PEM.encode()  # CA endpoint: PEM bundle [ASK, ARK]
        return _VCEK_DER  # VCEK endpoint: RAW DER (starts 0x30)

    ka._kds_get = fake  # type: ignore[assignment]
    out = ka._snp_cert_chain_augment(_report(), [])
    assert [e["cert_type"] for e in out] == ["VCEK", "ASK", "ARK"]
    assert out[0]["data"] == list(_VCEK_DER)


def main() -> int:
    print("== SNP cert-chain delivery (VCEK + ASK/ARK via KDS) ==")
    for fn in (
        test_empty_chain_fetches_full_vcek_ask_ark,
        test_coco_vcek_gets_only_missing_ca,
        test_complete_chain_unchanged_no_kds_call,
        test_kds_unreachable_leaves_original_chain,
        test_vcek_fetch_fail_does_not_emit_bare_ca,
        test_no_double_append,
        test_vcek_as_raw_der_is_parsed,
    ):
        try:
            fn()
            check(fn.__name__, True)
        except Exception as exc:  # noqa: BLE001
            check(fn.__name__, False, repr(exc))

    failed = [n for n, ok, _ in _results if not ok]
    print(f"\n{len(_results) - len(failed)}/{len(_results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
