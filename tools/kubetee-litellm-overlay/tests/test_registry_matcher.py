#!/usr/bin/env python3
"""Offline regression for the SIGNED reference-registry matcher + path fix.

Run from anywhere; needs no cluster, no Trustee, no network. Stubs the
`litellm` package and exercises the pure registry logic in kubetee_attestation:

  * the `any-active-record` match (a drifted register matches some record)
  * expired / deprecated record REJECTION (moved past, next record tried)
  * tampered-registry SIGNATURE rejection (Ed25519 over RFC8785 minus `signature`)
  * ROLE gating (a record with the wrong role cannot approve)
  * the `_backend_attest_url` `/v1` path fix (backend route is at root)

Exit 0 = all pass. This mirrors tests/test_breaker.py (run both).
"""
from __future__ import annotations

import asyncio
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
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{(' — ' + detail) if detail else ''}")


# --- synthetic fixtures -----------------------------------------------------
CFG = "0484a58e5927efd31bf871c74bcc9f1768f4335bb92340176989b3c5b320f934" "1d772b9e3e9c4fe4d824613cc19e6e0b"
GOOD_REGS = {
    "mrtd": "aa" * 48,
    "mrconfigid": CFG,
    "rtmr0": "11" * 48,
    "rtmr1": "22" * 48,
    "rtmr2": "33" * 48,
    "rtmr3": "44" * 48,
}


def _record(rec_id: str, *, status: str = "active", valid_until: str = "2099-01-01T00:00:00Z", role: str = "image-gen", model: str = "xiaomi/mimo-v2.6-pro", meas: dict | None = None) -> dict:
    return {
        "id": rec_id,
        "model": model,
        "role": role,
        "status": status,
        "valid_until": valid_until,
        "measurements": dict(meas or GOOD_REGS),
    }


def _registry(records: list[dict]) -> dict:
    return {"schema": "kubetee.tee-measurements-registry/1", "records": records}


def main() -> int:
    print("== reference-registry matcher ==")

    # 1. any-active-record: exact match on a single active record.
    ok, rid = ka._match_registry_record(dict(GOOD_REGS), [_record("mimo-1")])
    check("any-active-record match approves", ok and rid == "mimo-1", f"approved={ok} id={rid}")

    # 2. match against the SECOND of several active records (any-active-record).
    drifted = dict(GOOD_REGS, rtmr2="ee" * 48)  # only rec B matches
    rec_a = _record("A", meas=dict(GOOD_REGS))
    rec_b = _record("B", meas=dict(GOOD_REGS, rtmr2="ee" * 48))
    ok, rid = ka._match_registry_record(drifted, [rec_a, rec_b])
    check("any-active-record matches the 2nd record", ok and rid == "B", f"approved={ok} id={rid}")

    # 3. a field the record does not declare cannot block a match (None cannot trip).
    partial = _record("partial", meas={"mrtd": "aa" * 48})  # only mrtd declared
    ok, rid = ka._match_registry_record(dict(GOOD_REGS, rtmr0="zz" * 48), [partial])
    check("undeclared register cannot block a match", ok and rid == "partial", f"approved={ok} id={rid}")

    # 4. NO active record matches -> rejected (registry-no-match).
    ok, reason = ka._match_registry_record(dict(GOOD_REGS, rtmr2="ee" * 48), [rec_a])
    check("no matching record -> rejected", not ok and "registry-no-match" in reason, reason)

    print("== expired / deprecated record rejection ==")

    # 5. an EXPIRED record is deprecated and never matches (next record tried).
    expired = _record("old", valid_until="2020-01-01T00:00:00Z")  # would otherwise match
    ok, reason = ka._match_registry_record(dict(GOOD_REGS), [expired])
    check("expired record rejected", not ok and "no-active-record" in reason, reason)

    # 6. an explicitly deprecated/revoked record is skipped even if fresh.
    for status in ("deprecated", "revoked", "retired"):
        rec = _record(f"dep-{status}", status=status)
        ok, reason = ka._match_registry_record(dict(GOOD_REGS), [rec])
        check(f"status={status} record rejected", not ok and "no-active-record" in reason, reason)

    # 7. expired matching record + active NON-matching -> only the active one
    #    governs (rejects via registry-no-match; the expired record is not used).
    ok, reason = ka._match_registry_record(
        dict(GOOD_REGS), [expired, _record("A", meas=dict(GOOD_REGS, rtmr2="ee" * 48))]
    )
    check("expired cannot rescue a non-matching active set", not ok and "registry-no-match" in reason, reason)

    print("== registry signature (Ed25519 / RFC8785) ==")

    # 8. tampered registry -> signature fails to verify (rejection).
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        check("signature tests", False, "cryptography not installed")
    else:
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw()

        def signed_registry(records: list[dict]) -> dict:
            reg = _registry(records)
            sig = priv.sign(ka._jcs({k: v for k, v in reg.items() if k != "signature"}))
            import base64 as _b

            reg["signature"] = {"alg": "ed25519", "sig": _b.b64encode(sig).decode("ascii")}
            return reg

        saved_key = ka._REGISTRY_PUBLIC_KEY_B64
        import base64 as _b

        ka._REGISTRY_PUBLIC_KEY_B64 = _b.b64encode(pub).decode("ascii")

        good = signed_registry([_record("mimo-1")])
        check("signed registry verifies", ka._verify_registry_signature(good), "")

        tampered = signed_registry([_record("mimo-1")])
        tampered["records"][0]["measurements"]["mrtd"] = "ee" * 48  # mutate post-sign
        check("tampered registry rejected", not ka._verify_registry_signature(tampered), "")

        # wrong pinned key -> reject
        other = Ed25519PrivateKey.generate()
        ka._REGISTRY_PUBLIC_KEY_B64 = _b.b64encode(other.public_key().public_bytes_raw()).decode("ascii")
        check("wrong-key signature rejected", not ka._verify_registry_signature(good), "")

        # no pinned key -> matching still runs (signature not checked)
        ka._REGISTRY_PUBLIC_KEY_B64 = ""
        check("no pinned key -> signature not enforced", ka._verify_registry_signature(good), "")

        ka._REGISTRY_PUBLIC_KEY_B64 = saved_key

    print("== role gating ==")

    # 9. a record with the WRONG role cannot approve. The role check below
    #    mirrors the role gate in _verify_backend_evidence (image-gen).
    ok, rid = ka._match_registry_record(dict(GOOD_REGS), [_record("wrong-role", role="llm-gen")])
    check("role record structurally matches registers", ok, f"(register gate alone: {rid})")
    trips, _ = ka._verify_backend_evidence(
        {"tee": "tdx", "role": "llm-gen", "claims": {"quote": {"body": {
            "mr_td": GOOD_REGS["mrtd"], "mr_config_id": CFG,
            "rtmr_0": GOOD_REGS["rtmr0"], "rtmr_1": GOOD_REGS["rtmr1"],
            "rtmr_2": GOOD_REGS["rtmr2"], "rtmr_3": GOOD_REGS["rtmr3"]}}}}
    )
    check("wrong role trips the verifier (role gate)", any("role-mismatch" in t for t in trips), f"trips={trips}")

    # 10. full verify with a matching registry record -> no trips (approved).
    async def _reg():
        return _registry([_record("mimo-1")])

    ka._load_registry = _reg
    async def _observe(ev):
        await ka._observe_backend_evidence("ep-reg", ev)

    ka._breakers.clear()
    # a TDX envelope carries a `quote` (the extractor reads `claims` only after a
    # quote is present) — add a dummy base64 quote so the claims path runs.
    import base64 as _b64mod

    dummy_quote = _b64mod.b64encode(b"\x00" * 48 + b"\x11" * 584).decode("ascii")
    ev_ok = {"tee": "tdx", "role": "image-gen", "quote": dummy_quote,
             "claims": {"quote": {"body": {
        "mr_td": GOOD_REGS["mrtd"], "mr_config_id": CFG,
        "rtmr_0": GOOD_REGS["rtmr0"], "rtmr_1": GOOD_REGS["rtmr1"],
        "rtmr_2": GOOD_REGS["rtmr2"], "rtmr_3": GOOD_REGS["rtmr3"]}}},
        "epoch": {"id": "e", "valid_until": "2099-01-01T00:05:00Z"}}
    asyncio.run(_observe(ev_ok))
    check("registry match keeps breaker CLOSED", not ka.breaker_state("ep-reg")["open"],
          ka.breaker_state("ep-reg")["state"])

    print("== _backend_attest_url /v1 path fix ==")
    # 11. api_base ending in /v1 -> the /v1 is STRIPPED (backend route is root).
    u = ka._backend_attest_url("https://mimo-svc.nemo.svc.cluster.local:8443/v1")
    check("/v1 stripped to root evidence path",
          u == "https://mimo-svc.nemo.svc.cluster.local:8443/kubetee/evidence", u)
    # 12. an api_base without /v1 is used as-is (no double path).
    u2 = ka._backend_attest_url("https://mimo-svc.nemo.svc.cluster.local:8443")
    check("no-/v1 api_base unchanged",
          u2 == "https://mimo-svc.nemo.svc.cluster.local:8443/kubetee/evidence", u2)
    # 13. trailing slash tolerated.
    u3 = ka._backend_attest_url("https://mimo-svc:8443/v1/")
    check("trailing slash tolerated",
          u3 == "https://mimo-svc:8443/kubetee/evidence", u3)

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
