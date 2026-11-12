"""Native Management API contract, with no SQL, Prisma, database or Docker.

The default tests use HTTP transport doubles. An explicit staging credential
and verified hostname additionally opt into the real create/read/update probe.
All live keys are disabled at creation and forced back to zero budget in
``finally``. Chain settlement and positive-budget credit are never exercised.
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
            "max_budget": 0.0, "spend": 0.0, "blocked": True,
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
async def test_management_api_enterprise_and_atomic_credit_fail_closed():
    pending = {"reference": {"amount_units": 1_000_000_000}}
    from types import SimpleNamespace
    expected = {"pending": pending, "delta_units": 1_000_000_000}
    row = SimpleNamespace(metadata={"gamma": expected}, max_budget="0", spend="0")
    class ExactHotkey:
        async def find_exact_hotkey(self, hotkey):
            assert hotkey == HK
            return row
    async def regenerate(request):
        return httpx.Response(500, request=request, json={"error": {"message":
            "Regenerating Virtual Keys is an Enterprise feature, You must be a LiteLLM Enterprise user"}})
    transport = httpx.MockTransport(regenerate)
    async with httpx.AsyncClient(base_url="https://gateway.test", transport=transport) as client:
        with pytest.raises(mg.ManagingConflict, match="Enterprise feature.*LiteLLM Enterprise user"):
            await NativeManagementHTTP(client).call("POST", "/key/regenerate", {"key": "test-token"})
    with pytest.raises(mg.ManagingConflict, match="atomic credit CAS.*activation remains gated"):
        await mg.NativeKeys.compare_checkpoint(
            ExactHotkey(), HK, expected, {"pending": None, "delta_units": 0}, "0", "0", target_max_budget="1",
        )
    assert row.metadata == {"gamma": expected} and row.max_budget == "0" and row.spend == "0"
    # Routing through an ordinary /key/update request does not demonstrate that
    # both fields changed atomically. The worker activation gate remains closed.
