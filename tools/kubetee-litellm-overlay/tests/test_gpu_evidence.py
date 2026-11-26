#!/usr/bin/env python3
"""Offline regression for the NIM GPU evidence collector (kubetee_gpu_evidence).

Run from anywhere; needs no cluster, no GPUs, no Trustee, no network. Exercises
the pure SPDM framing, nonce binding, and NVAT serialization against CoCo
Trustee's byte-exact contract (deps/verifier/src/nvidia/{spdm_request,report,
nvat}.rs). A ``FakeCollector`` returns synthetic SPDM-shaped reports so the
framing + nonce-binding + composite assembly are all verified offline.

Exit 0 = all pass. Mirrors test_relay_l2.py / test_breaker.py.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OVERLAY = os.path.dirname(HERE)
sys.path.insert(0, OVERLAY)

import kubetee_gpu_evidence as kg  # noqa: E402

_results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    _results.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{(' — ' + detail) if detail else ''}")


NONCE_HEX = "ab" * 32  # 64 hex chars -> 32 bytes
NONCE = bytes.fromhex(NONCE_HEX)


def _fake_report(nonce: bytes, response_body: bytes, sig_len: int = 96) -> bytes:
    """Build a synthetic GPU report: request(37B) || response || signature(sig_len)."""
    request = kg.build_get_measurements_request(nonce)
    signature = b"\x11" * sig_len
    return request + response_body + signature


class FakeCollector:
    """Returns a nonce-bound synthetic report + a fixed PEM cert chain."""

    def __init__(self, cert_pem: str, wrong_nonce: bool = False):
        self.cert_pem = cert_pem
        self.wrong_nonce = wrong_nonce
        self.calls: list[int] = []

    def collect(self, index: int, nonce: bytes) -> kg.DeviceEvidence:
        self.calls.append(index)
        bound = b"\x22" * kg.SPDM_NONCE_SIZE if self.wrong_nonce else nonce
        report = _fake_report(bound, b"measurement-record-data")
        return kg.DeviceEvidence(
            arch="HOPPER",
            uuid=f"GPU-{index}",
            evidence=report,
            certificate=self.cert_pem,
        )


CERT_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    + base64.b64encode(b"leaf-cert-der").decode("ascii")
    + "\n-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\n"
    + base64.b64encode(b"ca-cert-der").decode("ascii")
    + "\n-----END CERTIFICATE-----\n"
)


def test_request_framing_byte_exact():
    req = kg.build_get_measurements_request(NONCE_HEX)
    ok = (
        len(req) == 37
        and req[0] == 0x11
        and req[1] == 0xE0
        and req[4:36] == NONCE
        and req[36] == 0x00
    )
    check("request_framing_byte_exact", ok, f"len={len(req)} ver={req[0]:#04x} code={req[1]:#04x}")


def test_request_nonce_at_offset_4_36():
    req = kg.build_get_measurements_request(NONCE_HEX)
    check("request_nonce_at_offset_4_36", req[4:36] == NONCE)


def test_split_report_matches_trustee():
    report = _fake_report(NONCE, b"response-body-here")
    signed, sig = kg.split_report(report, 96)
    # Trustee: signed = report[..len-96]; sig = report[len-96:]; total = 37+body+96
    ok = len(sig) == 96 and signed == report[:-96] and sig == report[-96:]
    check("split_report_matches_trustee", ok, f"signed={len(signed)} sig={len(sig)}")


def test_nonce_in_report_reads_request():
    report = _fake_report(NONCE, b"resp")
    check("nonce_in_report_reads_request", kg.nonce_in_report(report) == NONCE)


def test_normalize_nonce_accepts_hex_and_bytes():
    ok = kg.normalize_nonce(NONCE_HEX) == NONCE and kg.normalize_nonce(NONCE) == NONCE
    check("normalize_nonce_accepts_hex_and_bytes", ok)


def test_normalize_nonce_rejects_bad():
    raised = 0
    for bad in ("", "ab" * 31, "zz" * 32, b"\x00" * 31, 123):
        try:
            kg.normalize_nonce(bad)
        except kg.GpuEvidenceError:
            raised += 1
    check("normalize_nonce_rejects_bad", raised == 5, f"rejected {raised}/5")


def test_nvat_json_matches_trustee_shape():
    dev = kg.DeviceEvidence("hopper", "GPU-0", _fake_report(NONCE, b"body"), CERT_PEM)
    js = kg.devices_to_nvat_json([dev], NONCE_HEX)
    parsed = json.loads(js)
    entry = parsed[0]
    # Trustee keys + arch uppercased + nonce lower-hex + evidence base64 + cert verbatim
    expected_evidence = base64.b64encode(dev.evidence).decode("ascii")
    ok = (
        set(entry) == {"arch", "nonce", "evidence", "certificate"}
        and entry["arch"] == "HOPPER"
        and entry["nonce"] == NONCE_HEX
        and entry["evidence"] == expected_evidence
        and entry["certificate"] == CERT_PEM
    )
    check("nvat_json_matches_trustee_shape", ok, f"keys={sorted(entry)}")


def test_nvat_nonce_identical_across_devices():
    devs = [
        kg.DeviceEvidence("HOPPER", f"GPU-{i}", _fake_report(NONCE, b"b"), CERT_PEM)
        for i in range(3)
    ]
    parsed = json.loads(kg.devices_to_nvat_json(devs, NONCE_HEX))
    nonces = {e["nonce"] for e in parsed}
    check("nvat_nonce_identical_across_devices", len(nonces) == 1 and len(parsed) == 3)


def test_collect_self_check_accepts_bound():
    coll = FakeCollector(CERT_PEM)
    try:
        devs = kg.collect_gpu_evidence(NONCE_HEX, coll, 2)
        ok = len(devs) == 2 and coll.calls == [0, 1]
    except Exception as e:
        ok = False
        devs = []
        _results[-1] = ("collect_self_check_accepts_bound", False, str(e))
    check("collect_self_check_accepts_bound", ok, f"{len(devs)} devices")


def test_collect_fails_closed_on_wrong_nonce():
    coll = FakeCollector(CERT_PEM, wrong_nonce=True)
    raised = False
    try:
        kg.collect_gpu_evidence(NONCE_HEX, coll, 1)
    except kg.GpuEvidenceError:
        raised = True
    check("collect_fails_closed_on_wrong_nonce", raised)


def test_evidence_digest_nonce_sensitive():
    dev = kg.DeviceEvidence("HOPPER", "GPU-0", _fake_report(NONCE, b"body"), CERT_PEM)
    js1 = kg.devices_to_nvat_json([dev], NONCE_HEX)
    js2 = kg.devices_to_nvat_json([dev], "cd" * 32)
    d1 = kg.evidence_digest(js1, NONCE_HEX)
    d2 = kg.evidence_digest(js2, "cd" * 32)
    # Digest is stable for same input, differs across nonce.
    d1b = kg.evidence_digest(js1, NONCE_HEX)
    check(
        "evidence_digest_nonce_sensitive",
        d1 != d2 and d1 == d1b and d1.startswith("sha256:"),
    )


def test_composite_evidence_shape_and_rehash():
    coll = FakeCollector(CERT_PEM)
    doc = kg.collect_composite(
        {"quote": "cpu-quote-b64"}, NONCE_HEX, coll, 2, arch="hopper"
    )
    rehash = hashlib.sha256(
        doc["gpus_json"].encode("utf-8") + b"\x00" + NONCE
    ).hexdigest()
    ok = (
        doc["schema"] == kg.SCHEMA
        and doc["tee"] == "tdx"
        and doc["gpu_count"] == 2
        and doc["arch"] == "HOPPER"
        and doc["nonce"] == NONCE_HEX
        and doc["cpu"] == {"quote": "cpu-quote-b64"}
        and doc["evidence_digest"] == "sha256:" + rehash
        and isinstance(doc["gpus"], list) and len(doc["gpus"]) == 2
    )
    check("composite_evidence_shape_and_rehash", ok, doc["evidence_digest"][:20])


def test_split_report_rejects_degenerate():
    bad = 0
    for report, sig_len in ((b"short", 96), (b"x" * 50, 50), (b"x" * 50, 0)):
        try:
            kg.split_report(report, sig_len)
        except kg.GpuEvidenceError:
            bad += 1
    check("split_report_rejects_degenerate", bad == 3, f"rejected {bad}/3")


def test_evidence_b64_normalizes_hex_passthrough_b64():
    raw = b"raw-report-bytes"
    from_bytes = kg._evidence_b64(raw)
    from_hex = kg._evidence_b64(raw.hex())
    from_b64 = kg._evidence_b64(base64.b64encode(raw).decode("ascii"))
    expect = base64.b64encode(raw).decode("ascii")
    check(
        "evidence_b64_normalizes_hex_passthrough_b64",
        from_bytes == expect == from_hex == from_b64,
    )


def main() -> int:
    print("kubetee_gpu_evidence offline tests:")
    test_request_framing_byte_exact()
    test_request_nonce_at_offset_4_36()
    test_split_report_matches_trustee()
    test_nonce_in_report_reads_request()
    test_normalize_nonce_accepts_hex_and_bytes()
    test_normalize_nonce_rejects_bad()
    test_nvat_json_matches_trustee_shape()
    test_nvat_nonce_identical_across_devices()
    test_collect_self_check_accepts_bound()
    test_collect_fails_closed_on_wrong_nonce()
    test_evidence_digest_nonce_sensitive()
    test_composite_evidence_shape_and_rehash()
    test_split_report_rejects_degenerate()
    test_evidence_b64_normalizes_hex_passthrough_b64()

    passed = sum(1 for _, ok, _ in _results if ok)
    total = len(_results)
    print(f"\n{passed}/{total} passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
