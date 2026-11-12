"""Self-contained SN90 scope and private-response validation.
No Bittensor SDK, discovery routes, Redis, or chain client dependency.
"""
from __future__ import annotations

import base64
from decimal import Decimal, InvalidOperation
from typing import Any

GENESIS = "0x2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03"


def assert_hotkey(value: str) -> None:
    """Base58Check Bitcoin-style checksum plus Substrate's 'SS58PRE' prefix."""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = 0
    if not isinstance(value, str) or not 47 <= len(value) <= 49 or any(c not in alphabet for c in value):
        raise ValueError("invalid SS58 account id")
    for char in value:
        number = number * 58 + alphabet.index(char)
    encoded = number.to_bytes((number.bit_length() + 7) // 8, "big")
    encoded = b"\0" * (len(value) - len(value.lstrip("1"))) + encoded
    if len(encoded) != 35 or encoded[0] != 42:
        raise ValueError("only a canonical Substrate 32-byte account is accepted")
    import hashlib
    if hashlib.blake2b(b"SS58PRE" + encoded[:-2], digest_size=64).digest()[:2] != encoded[-2:]:
        raise ValueError("SS58 checksum mismatch")


def settlement_reference(*, netuid: int, hotkey: str, observation_hash: str, units: int) -> str:
    assert_hotkey(hotkey)
    if netuid != 90 or type(units) is not int or not 0 < units <= 2**64 - 1:
        raise ValueError("only positive exact SN90 units")
    if not isinstance(observation_hash, str) or len(observation_hash) != 66 or not observation_hash.startswith("0x"):
        raise ValueError("exact lowercase finalized observation hash required")
    bytes.fromhex(observation_hash[2:])
    if observation_hash.lower() != observation_hash:
        raise ValueError("lowercase finalized observation hash required")
    import hashlib
    return "0x" + hashlib.sha256(
        f"kubetee-sn90-settlement-v1\0{GENESIS}\0{netuid}\0{hotkey}\0{observation_hash}\0{units}".encode()
    ).hexdigest()


def positive_credit(result: dict[str, Any]) -> bool:
    try:
        return Decimal(str(result["remaining_credit"])) > 0
    except (InvalidOperation, KeyError, TypeError, ValueError):
        return False


def validate_claimed_result(result: object, first_claim: bool = False) -> dict[str, Any]:
    if not isinstance(result, dict) or result.get("status") not in {"provisioned", "funded"}:
        raise ValueError("no funded provisioned result")
    if type(first_claim) is not bool:
        raise ValueError("claim action must be explicit")
    if first_claim and result.get("has_positive_chain_settlement") is not True:
        raise ValueError("initial key requires finalized settlement")
    if not positive_credit(result):
        raise ValueError("new native key requires positive credit")
    reference = result.get("reconciliation_reference")
    key = result.get("api_key")
    if not isinstance(reference, str) or not reference:
        raise ValueError("missing chain settlement reference")
    if not isinstance(key, str) or not key.startswith("sk-") or len(key) < 16:
        raise ValueError("invalid native key")
    return {"status": "provisioned", "api_key": key, "remaining_credit": result["remaining_credit"]}
