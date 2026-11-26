#!/usr/bin/env python3
"""Offline regression for the gateway measurement-drift circuit breaker.

Run from anywhere; needs no cluster, no Trustee, no backend. Stubs the
`litellm` package (only the CustomLogger base class is touched at import) and
exercises the pure verification + state-machine logic in kubetee_attestation:

  * the seven TRIP conditions (role/initdata/mrtd/rtmr0-3/ovmf drift)
  * the DEGRADE-not-trip path (freshness gaps never block)
  * the None-expectation guard (not-yet-captured registers cannot trip)
  * the CLOSED -> OPEN -> (no auto-clear) lifecycle
  * enforce-on auto-block + alert dispatch (monkeypatched, no network)

Exit 0 = all pass. This mirrors nim/eastwest/verify-resource-policy.py.
"""
from __future__ import annotations

import asyncio
import base64
import copy
import os
import sys
import types

# --- minimal litellm stub (import surface only) -----------------------------
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


def _b64(buf: bytes) -> str:
    return base64.b64encode(buf).decode("ascii").rstrip("=")


def _tdx_body(mrtd, cfg, r0, r1, r2, r3) -> bytes:
    """AUTHORITATIVE TDReport10 body (584 bytes) for the raw-quote fallback.

    Field offsets (body-relative) match dcap-qvl's ``TDReport10`` — the struct
    the validated gm-miner/attestd ``kubetee_verify`` reads. Each non-register
    field gets a distinct filler byte so a wrong-offset read cannot alias a
    register (the earlier wrong-offset extractor slipped through because this
    builder mirrored its layout). report_data lands at quote-absolute 568,
    matching kubetee_binding.py's documented REPORTDATA offset.
    """

    def fill(n, b):
        return bytes([b]) * n

    return (
        fill(16, 0x10)                    # tee_tcb_svn      [  0: 16]
        + fill(48, 0x20)                  # mr_seam          [ 16: 64]
        + fill(48, 0x30)                  # mr_signer_seam   [ 64:112]
        + fill(8, 0x40)                   # seam_attributes  [112:120]
        + fill(8, 0x50)                   # td_attributes    [120:128]
        + fill(8, 0x60)                   # xfam             [128:136]
        + bytes.fromhex(mrtd)             # mr_td            [136:184]
        + bytes.fromhex(cfg)              # mr_config_id     [184:232]
        + fill(48, 0x70)                  # mr_owner         [232:280]
        + fill(48, 0x80)                  # mr_owner_config  [280:328]
        + bytes.fromhex(r0)               # rt_mr0           [328:376]
        + bytes.fromhex(r1)               # rt_mr1           [376:424]
        + bytes.fromhex(r2)               # rt_mr2           [424:472]
        + bytes.fromhex(r3)               # rt_mr3           [472:520]
        + fill(64, 0x90)                  # report_data      [520:584]
    )


def _good_evidence(**over):
    """A healthy TDX backend envelope matching every pinned expectation."""
    mrconfigid = ka._EXPECTED_BACKEND["mrconfigid"]
    body = _tdx_body(
        mrtd="aa" * 48,
        cfg=mrconfigid,
        r0="11" * 48,
        r1="22" * 48,
        r2="33" * 48,
        r3="44" * 48,
    )
    quote = _b64(b"\x00" * 48 + body)  # 48-byte quote header + TDReport10 body
    ev = {
        "subject": "nim-terminator",
        "tee": "tdx",
        "role": "image-gen",
        "runtime_class": "kata-qemu-nvidia-gpu-tdx-runtime-rs",
        "quote": quote,
        "quote_sha256": "d" * 64,
        "epoch": {
            "id": "epoch-abc",
            "issued_at": "2099-01-01T00:00:00Z",
            "valid_until": "2099-01-01T00:05:00Z",
        },
    }
    ev.update(over)
    return ev


def _regs(**over):
    mrconfigid = ka._EXPECTED_BACKEND["mrconfigid"]
    regs = {
        "mr_td": "aa" * 48,
        "mr_config_id": mrconfigid,
        "rtmr_0": "11" * 48,
        "rtmr_1": "22" * 48,
        "rtmr_2": "33" * 48,
        "rtmr_3": "44" * 48,
    }
    regs.update(over)
    return {"claims": {"quote": {"body": regs}}}


_results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    _results.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{(' — ' + detail) if detail else ''}")


def expect_trips(ev, want_substr, label):
    trips, gaps = ka._verify_backend_evidence(ev)
    ok = any(want_substr in t for t in trips)
    check(label, ok, f"trips={trips}")


def expect_no_trips(ev, label):
    trips, _ = ka._verify_backend_evidence(ev)
    check(label, trips == [], f"trips={trips}")


def main() -> int:
    print("== measurement-drift circuit breaker ==")

    # 1. healthy envelope -> no trips, no gaps
    trips, gaps = ka._verify_backend_evidence(_good_evidence())
    check("healthy -> no trip, no gap", trips == [] and gaps == [], f"trips={trips} gaps={gaps}")

    # 2. role mismatch -> trip
    expect_trips(_good_evidence(role="llm-gen"), "role-mismatch", "(1) role-mismatch trips")

    # 3. initdata (mrconfigid) drift -> trip  (via parsed claims path)
    drifted = _good_evidence(**_regs(mr_config_id="ee" * 48))
    expect_trips(drifted, "mrconfigid-drift", "(2) mrconfigid drift trips")

    # 4..8 + 10: register drift trips. These registers are PENDING-CAPTURE in
    # the reference record (None -> cannot trip by design, #13 below), so pin
    # them here to the verified-good values first, then drift the evidence —
    # exactly the capture-then-drift sequence in production.
    saved_refs = {n: ka._EXPECTED_BACKEND[n] for n in ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3")}
    ka._EXPECTED_BACKEND.update({"mrtd": "aa" * 48, "rtmr0": "11" * 48, "rtmr1": "22" * 48, "rtmr2": "33" * 48, "rtmr3": "44" * 48})

    expect_trips(_good_evidence(**_regs(mr_td="ee" * 48)), "mrtd-drift", "(3) mrtd drift trips")

    # 5-8. rtmr0..3 drift -> trip (parsed claims)
    for i in range(4):
        key = f"rtmr_{i}"
        expect_trips(
            _good_evidence(**_regs(**{key: "ee" * 48})),
            f"rtmr{i}-drift",
            f"({4 + i}) rtmr{i} drift trips",
        )

    # 10. fallback register reconstruction (raw quote, no parsed claims)
    fallback_ev = _good_evidence()
    fallback_ev["quote"] = _b64(b"\x00" * 48 + _tdx_body("ee" * 48, ka._EXPECTED_BACKEND["mrconfigid"], "11" * 48, "22" * 48, "33" * 48, "44" * 48))
    expect_trips(fallback_ev, "mrtd-drift", "(10) raw-quote fallback reconstruction trips on mrtd drift")

    ka._EXPECTED_BACKEND.update(saved_refs)  # restore to PENDING (None) state

    # 9. ovmf drift -> trip
    expect_trips(
        _good_evidence(ovmf_fd_sha256="f" * 64),
        "ovmf-drift",
        "(9) ovmf drift trips",
    )

    # 10 covered above (fallback reconstruction).

    # 11. TDX evidence with no readable MRCONFIGID -> trip (fail closed, opaque guest)
    opaque = _good_evidence(**_regs(mr_config_id=None))
    del opaque["claims"]["quote"]["body"]["mr_config_id"]
    expect_trips(opaque, "mrconfigid-absent", "(11) opaque TDX guest trips")

    # 12. freshness gap -> DEGRADE, never trip
    stale = _good_evidence(
        epoch={"id": "e", "issued_at": "2020-01-01T00:00:00Z", "valid_until": "2020-01-01T00:05:00Z"}
    )
    trips, gaps = ka._verify_backend_evidence(stale)
    check("expired epoch degrades, does not trip", trips == [] and any("epoch-expired" in g for g in gaps), f"trips={trips} gaps={gaps}")

    no_epoch = _good_evidence(epoch={})
    trips, gaps = ka._verify_backend_evidence(no_epoch)
    check("absent epoch degrades, does not trip", trips == [] and any("epoch-absent" in g for g in gaps), f"gaps={gaps}")

    # 13. None expectation cannot trip (unset register refs)
    saved = ka._EXPECTED_BACKEND["mrtd"]
    ka._EXPECTED_BACKEND["mrtd"] = None
    expect_no_trips(_good_evidence(**_regs(mr_td="ee" * 48)), "(13) unset mrtd expectation cannot trip")
    ka._EXPECTED_BACKEND["mrtd"] = saved  # restore

    # 14. SNP evidence -> register trip conditions cannot fire (by design)
    snp_ev = {
        "tee": "snp",
        "role": "image-gen",
        "snp": {"measurement": "aa" * 64},
        "epoch": {"id": "e", "valid_until": "2099-01-01T00:05:00Z"},
    }
    expect_no_trips(snp_ev, "(14) SNP guest never trips on TDX registers")

    # --- state machine + enforce (monkeypatched, no network) ----------------
    print("== breaker state machine + enforcement ==")
    posted: list[str] = []

    async def fake_block_alert(reason):
        posted.append(reason)

    async def _run_state_machine() -> None:
        async with ka._breaker_lock:
            ka._breakers.clear()
            ka._breaker_notified.clear()

        # Hermetic: this suite exercises the BREAKER on synthetic measurements,
        # not the reference REGISTRY. Stub the registry loader (its own suite is
        # test_registry_matcher.py) so the env _EXPECTED_BACKEND fallback — the
        # per-field drift gate — is what runs. Otherwise a live registry fetch
        # would treat the synthetic 0xeeee regs as "no active record" drift.
        async def _no_registry():
            return None

        ka._load_registry = _no_registry

        ev = _good_evidence(**_regs(mr_config_id="ee" * 48))
        await ka._observe_backend_evidence("ep1", ev)

        # a healthy observation after a trip must NOT auto-clear (no auto-reset)
        await ka._observe_backend_evidence("ep1", _good_evidence())

        # freshness gap -> DEGRADED headers, still not blocked
        await ka._observe_backend_evidence("ep2", stale)

        # enforce path: monkeypatch the dispatcher, ensure one trip -> one call
        ka._post_block_and_alert = fake_block_alert
        ka._BREAKER_ENFORCE = True
        await ka._observe_backend_evidence("ep3", ev)
        await ka._observe_backend_evidence("ep3", ev)  # dedup

    asyncio.run(_run_state_machine())

    st = ka.breaker_state("ep1")
    check("drift -> OPEN + trip recorded", st["state"] == "OPEN" and st["open"] and st["trips"] == 1, str(st["state"]))

    guard = ka.breaker_guard("ep1")
    check(
        "OPEN -> 503 auto-block headers",
        guard is not None and guard.get("X-KubeTEE-Breaker-State") == "OPEN" and "auto-block" in guard.get("X-KubeTEE-Breaker-Action", ""),
        str(guard),
    )

    check("healthy after trip does NOT auto-clear", ka.breaker_state("ep1")["state"] == "OPEN")

    guard2 = ka.breaker_guard("ep2")
    check(
        "freshness gap -> DEGRADED (not blocked)",
        guard2 is not None and guard2.get("X-KubeTEE-Breaker-State") == "DEGRADED" and "Action" not in guard2,
        str(guard2),
    )

    check("enforce dispatches once per distinct trip", len(posted) == 1, f"calls={len(posted)}")

    failed = [r for r in _results if not r[1]]
    print(f"\n{_results and len(_results) - len(failed)}/{len(_results)} passed")
    if failed:
        print("FAILED:")
        for name, _, detail in failed:
            print(f"  - {name}: {detail}")
        return 1
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
