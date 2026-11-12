"""Native Management API contract, with no SQL, Prisma, database or Docker.

The default tests use HTTP transport doubles. An explicit staging credential
and verified hostname additionally opt into the real create/read/update probe.
All live keys are disabled at creation and forced back to zero budget in
``finally``. The live probe never exercises chain settlement or a positive
budget; the credit write is covered against the real adapter with doubles.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "tools/kubetee-litellm-overlay"))
import kubetee_gamma_management as mg

HK = "5E7G3rNBsLkneUmrDAhYUo1KRu2MrTMXivYX5vbWLcMUn3de"
SECOND_HK = "5FWaYw6QjKLxu1oDa8bTpBHjL9PrbvZsTqR9Hi1fiPUF97We"


class NativeManagementHTTP:
    """Use only LiteLLM Management HTTP routes, no storage backend."""
    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def call(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict:
        response = await self.client.request(method, path, json=body)
        if response.headers.get("content-type", "").split(";")[0] != "application/json":
            raise RuntimeError("native Management API returned no JSON")
        result = response.json()
        if response.status_code >= 400:
            message = json.dumps(result, separators=(",", ":"))
            raise mg.ManagingConflict(f"native Management API {response.status_code}: {message[:800]}")
        return result

    @staticmethod
    def row(result: dict, token: str) -> Any:
        info = result["info"]
        if info.get("key") is not None:
            raise mg.ManagingConflict("Management API unexpectedly returned a raw credential")
        from types import SimpleNamespace
        return SimpleNamespace(**info, token=token)

    async def generate(self, hotkey: str, checkpoint: dict) -> tuple[str, str]:
        raw = "sk-test-only-" + hashlib.sha256(hotkey.encode()).hexdigest()
        result = await self.call("POST", "/key/generate", {
            "key": raw, "key_alias": checkpoint["observation_coldkey"] + "-" + hotkey.lower(),
            "team_id": os.environ["KUBETEE_GAMMA_STAGING_TEAM_ID"],
            "max_budget": 0.0, "blocked": True,
            "models": ["z-ai/glm-5.3"],
            "metadata": {"gamma": checkpoint, "gamma_hotkey": hotkey,
                         "gamma_netuid": mg.NETUID, "gamma_network": mg.NETWORK},
        })
        if hashlib.sha256(raw.encode()).hexdigest() != result["token"]:
            raise mg.ManagingConflict("nonstandard raw-key hash response")
        if result["token_id"] != result["token"]:
            raise mg.ManagingConflict("nonstandard native token_id")
        return result["token"], raw


def checkpoint(height: int, hotkey: str) -> dict:
    return {
        "schema": 1, "network": "finney", "genesis_hash": mg.GENESIS,
        "netuid": 90, "observation_height": height,
        "observation_hash": "0x" + f"{height:064x}",
        "observation_coldkey": "synthetic-only-" + hotkey,
        "observation_spender": "synthetic-only-service-spender",
        "accepted_kind": "minted_pending", "delta_units": 0,
        "previous_units": 0, "receipt_ids": [], "total_settled_units": 0,
        "pending": None, "last_spent_height": None, "last_spent_amount": None,
        "last_spent_reference": None, "cap": None, "needs_cap_audit": False,
    }


@pytest.mark.asyncio
async def test_real_management_api_zero_credit_lifecycle():
    """Requires isolated staging team auth and a deliberately verified hostname.

    Do not set these variables in an ordinary test run. Raw credentials belong
    in the external CI secret environment, never in this source tree.
    """
    key = os.environ.get("KUBETEE_GAMMA_STAGING_TEAM_KEY")
    team = os.environ.get("KUBETEE_GAMMA_STAGING_TEAM_ID")
    host = os.environ.get("KUBETEE_GAMMA_NATIVE_VERIFIED_HOST")
    ttl = os.environ.get("KUBETEE_GAMMA_NATIVE_TTL")
    if not all((key, team, host, ttl)):
        pytest.skip("isolated staging team credential, verified hostname and TTL not requested")
    if host != "llm.kubetee.ai" or not 0 < int(ttl) <= 180:
        pytest.fail("staging API verification must expire within 180 seconds")
    async with httpx.AsyncClient(base_url="https://" + host, timeout=30,
                                 headers={"Authorization": "Bearer " + key}) as client:
        native = NativeManagementHTTP(client)
        tokens = []
        try:
            for index, hotkey in enumerate((HK, SECOND_HK), 1):
                token, raw = await native.generate(hotkey, checkpoint(index, hotkey))
                tokens.append(token)
                result = await native.call("GET", f"/key/info?key={token}")
                information = result["info"]
                assert information["team_id"] == team
                assert information["max_budget"] == 0.0
                assert information["blocked"] is True
                assert information["metadata"]["gamma"] == checkpoint(index, hotkey)
                listed = await native.call("GET", "/key/list?team_id=" + team + "&include_team_keys=true&return_full_object=true&size=100")
                matches = [row for row in listed["keys"] if row.get("token") == token]
                assert len(matches) == 1
                await native.call("POST", "/key/update", {
                    "key": token, "metadata": {"gamma": checkpoint(index, hotkey),
                    "gamma_hotkey": hotkey, "gamma_netuid": mg.NETUID, "gamma_network": mg.NETWORK},
                })
                result = await native.call("GET", f"/key/info?key={token}")
                assert result["info"]["max_budget"] == 0.0
                assert result["info"]["key_alias"] == checkpoint(index, hotkey)["observation_coldkey"] + "-" + hotkey.lower()
                result = await native.call("GET", f"/key/info?key={token}")
                assert result["info"]["max_budget"] == 0.0
                assert result["info"]["spend"] == 0.0
                # Optional live probe: do not enable a licensed feature or
                # substitute an update for the native atomic rotate operation.
                # Normal staging opt-in stops at stopped/zero usage lifecycle.
                if os.environ.get("KUBETEE_GAMMA_NATIVE_ROTATION_PROBE") != "1":
                    continue
                new = await client.post("/key/regenerate", json={
                    "key": token, "new_key": "sk-test-only-rotate-" + raw.removeprefix("sk-test-only-"),
                })
                if new.status_code == 403:
                    print("Native key/regenerate requires LiteLLM Enterprise; test gate closed")
                    continue
                assert new.status_code == 200, new.text
                refreshed = new.json()
                info = refreshed["info"]
                assert info["token"] != token
                tokens.append(info["token"])
                assert info["max_budget"] == 0.0 and info["blocked"] is True
                assert info["metadata"]["gamma"] == checkpoint(index, hotkey)
                assert info["key_alias"] == checkpoint(index, hotkey)["observation_coldkey"] + "-" + hotkey.lower()
                assert info["team_id"] == team and info.get("spend", 0.0) == 0.0
        finally:
            for token in tokens:
                await native.call("POST", "/key/update", {
                    "key": token, "blocked": True, "max_budget": 0.0,
                })
                information = (await native.call("GET", f"/key/info?key={token}"))["info"]
                assert information["blocked"] is True and information["max_budget"] == 0.0
                assert information["spend"] == 0.0
            if tokens:
                cleaned = await client.post("/key/delete", json={"keys": tokens})
                print({"native_cleanup_http": cleaned.status_code,
                       "keys": len(tokens), "positive_credit_attempted": False})


@pytest.mark.asyncio
async def test_native_regenerate_is_enterprise_gated_for_every_caller():
    """Verified on staging 2026-11-12 with team-key AND master-key auth."""
    async def regenerate(request):
        return httpx.Response(500, request=request, json={"error": {"message":
            "Regenerating Virtual Keys is an Enterprise feature, You must be a LiteLLM Enterprise user"}})
    transport = httpx.MockTransport(regenerate)
    async with httpx.AsyncClient(base_url="https://gateway.test", transport=transport) as client:
        with pytest.raises(mg.ManagingConflict, match="Enterprise feature.*LiteLLM Enterprise user"):
            await NativeManagementHTTP(client).call("POST", "/key/regenerate", {"key": "test-token"})


class RecordingNative:
    """Real NativeKeys.compare_checkpoint over a recorded native update."""
    def __init__(self, checkpoint: dict, *, max_budget: object = 0.0, blocked: bool = True,
                 spend: object = 0.0):
        from types import SimpleNamespace
        self.row = SimpleNamespace(token="0" * 64, blocked=blocked, max_budget=max_budget, spend=spend,
            metadata={"gamma": checkpoint, "gamma_hotkey": HK, "tenant_note": "kept"})
        self.updates: list[dict] = []

    async def find_exact_hotkey(self, hotkey):
        assert hotkey == HK
        return self.row

    async def update(self, row, *, metadata=None, max_budget=None, blocked=None):
        assert row is self.row
        self.updates.append({"metadata": metadata, "max_budget": max_budget, "blocked": blocked})
        row.metadata = metadata
        if max_budget is not None:
            row.max_budget = float(max_budget)
        if blocked is not None:
            row.blocked = blocked
        return row


def intent(total: int, amount: int, receipts: list | None = None) -> tuple[dict, dict]:
    receipts = receipts or []
    pending = {"pending": {"reference": {"amount_units": amount}}, "delta_units": amount,
               "total_settled_units": total, "receipt_ids": receipts}
    settled = {"pending": None, "delta_units": 0, "total_settled_units": total + amount,
               "receipt_ids": [*receipts, {"amount_units": amount}]}
    return pending, settled


@pytest.mark.asyncio
async def test_credit_is_one_native_update_of_checkpoint_and_budget():
    pending, settled = intent(0, 1_000_000_000)
    native = RecordingNative(pending)
    row = await mg.NativeKeys.compare_checkpoint(native, HK, pending, settled, "0", target_max_budget="1")
    # One write: receipt, allowance and first-credit enable travel together.
    assert native.updates == [{"metadata": {"gamma": settled, "gamma_hotkey": HK, "tenant_note": "kept"},
                               "max_budget": "1", "blocked": False}]
    assert mg.exact_units(row.max_budget) == mg.settled_total(row.metadata["gamma"]) == 1_000_000_000

    # Top-up: absolute new total, usage ignored, an operator block untouched.
    pending, topped = intent(1_000_000_000, 500_000_000, settled["receipt_ids"])
    native = RecordingNative(pending, max_budget=1.0, blocked=True, spend=0.30000000000000004)
    await mg.NativeKeys.compare_checkpoint(native, HK, pending, topped, "1", target_max_budget="1.5")
    assert native.updates == [{"metadata": {"gamma": topped, "gamma_hotkey": HK, "tenant_note": "kept"},
                               "max_budget": "1.5", "blocked": None}]
    assert native.row.blocked is True and native.row.spend == 0.30000000000000004


@pytest.mark.asyncio
@pytest.mark.parametrize("row_budget,claimed_budget,target,settled_after,reason", [
    (5.0, "5", "5.5", None, "not the settled Gamma total"),            # row edited outside Gamma
    (1.0, "1", "1.5", 1_400_000_000, "previous total \\+ proven"),      # total != receipts
    (1.0, "1", "1.6", None, "target max_budget is not the settled"),   # target != total
    (1.0, "2", "1.5", None, "unchanged version required"),             # stale caller view
])
async def test_credit_writes_nothing_unless_budget_is_the_settled_total(
        row_budget, claimed_budget, target, settled_after, reason):
    pending, topped = intent(1_000_000_000, 500_000_000)
    if settled_after is not None:
        topped["total_settled_units"] = settled_after
    native = RecordingNative(pending, max_budget=row_budget, blocked=False)
    with pytest.raises(mg.ManagingConflict, match=reason):
        await mg.NativeKeys.compare_checkpoint(native, HK, pending, topped, claimed_budget,
                                               target_max_budget=target)
    assert native.updates == [] and native.row.max_budget == row_budget
    assert native.row.metadata["gamma"] == pending


@pytest.mark.asyncio
async def test_credit_refuses_totals_native_float_money_cannot_hold():
    total = 12_345_678_123_456_789  # 12,345,678.123456789 Gamma: not a float64 round trip
    pending, topped = intent(total - 1, 1)
    native = RecordingNative(pending, max_budget="12345678.123456788", blocked=False)
    with pytest.raises(mg.ManagingConflict, match="not exactly representable"):
        await mg.NativeKeys.compare_checkpoint(native, HK, pending, topped, "12345678.123456788",
                                               target_max_budget="12345678.123456789")
    assert native.updates == []
    assert mg.native_budget("999999.999999999") == 999999.999999999


@pytest.mark.asyncio
async def test_native_update_sends_one_request_carrying_every_field(monkeypatch):
    """The adapter's update is a single native update_key_fn call, then a readback."""
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from litellm.proxy.management_endpoints import key_management_endpoints as native_api
    pending, settled = intent(0, 1_000_000_000)
    stored = SimpleNamespace(token="0" * 64, blocked=True, max_budget=0.0, spend=0.0,
                             metadata={"gamma": pending, "gamma_hotkey": HK})
    calls = []
    async def update_key_fn(*, request, data, user_api_key_dict, litellm_changed_by):
        sent = data.model_dump(exclude_unset=True)
        calls.append(sent)
        stored.metadata, stored.max_budget, stored.blocked = sent["metadata"], sent["max_budget"], sent["blocked"]
    monkeypatch.setattr(native_api, "update_key_fn", update_key_fn)
    monkeypatch.setattr(mg.NativeKeys, "admin", AsyncMock(return_value=None))
    async def readback(self, hotkey):
        assert hotkey == HK
        return stored
    monkeypatch.setattr(mg.NativeKeys, "find_exact_hotkey", readback)
    native = object.__new__(mg.NativeKeys)
    row = await native.compare_checkpoint(HK, pending, settled, "0", target_max_budget="1")
    assert calls == [{"key": "0" * 64, "metadata": {"gamma": settled, "gamma_hotkey": HK},
                      "max_budget": 1.0, "blocked": False}]
    assert row.blocked is False and row.max_budget == 1.0
