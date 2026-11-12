"""Public exact-H signing/claim contract; every chain/key fixture is synthetic."""
from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
import os
import subprocess
import shutil
from pathlib import Path

import bittensor as bt
import pytest
from bittensor_core import Keypair
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient, Response

MODULE = Path(__file__).resolve().parents[4] / "tools/kubetee-litellm-overlay/kubetee_gamma_claim.py"
SPEC = importlib.util.spec_from_file_location("kubetee_gamma_claim", MODULE)
assert SPEC and SPEC.loader
claim = importlib.util.module_from_spec(SPEC)
sys.modules["kubetee_gamma_claim"] = claim
SPEC.loader.exec_module(claim)


def new_hotkey():
    return Keypair.create_from_mnemonic(Keypair.generate_mnemonic(12), crypto_type=bt.CRYPTO_SR25519)


class SyntheticWorker:
    ready = True
    native_credit_callback_configured = True
    trusted_proxy_ips: tuple[str, ...] = ()

    def __init__(self):
        self.responses: list[tuple[int, dict]] = [(202, {"status": "pending", "reason": "chain_finalizing", "retry_after_seconds": 6})]
        self.funds: dict[str, dict] = {}
        self.keys: dict[str, str] = {}
        self.locks: dict[str, asyncio.Lock] = {}
        self.requests: list[dict] = []
        self.concurrent = 0
        self.max_concurrent = 0

    async def claim(self, body):
        self.requests.append(body)
        hotkey = body["hotkey_ss58"]
        if self.responses:
            return self.responses.pop(0)
        # Synthetic equivalent of the separate TEE worker's durable H lock.
        # Its chain settlement -> conditional max_budget operation -> established
        # key readback must be one fenced operation, not separate gateway calls.
        async with self.locks.setdefault(hotkey, asyncio.Lock()):
            self.concurrent += 1
            self.max_concurrent = max(self.max_concurrent, self.concurrent)
            await asyncio.sleep(0)
            credit = self.funds.setdefault(hotkey, {
                "max_budget": "2", "spend": "0", "remaining_credit": "2",
                "has_positive_chain_settlement": True,
                "reconciliation_reference": "block:extrinsic:GammaSpent",
            })
            key = self.keys.setdefault(hotkey, "sk-synthetic-" + hotkey[:10])
            self.concurrent -= 1
        return 200, {"status": "provisioned", "api_key": key, **credit}

    async def rotate(self, body):
        if self.responses:
            return self.responses.pop(0)
        hotkey = body["hotkey_ss58"]
        if hotkey not in self.funds or not claim.positive_credit(self.funds[hotkey]):
            return 403, {"status": "ineligible", "reason": "existing_positive_credit_required"}
        async with self.locks.setdefault(hotkey, asyncio.Lock()):
            self.keys[hotkey] = "sk-synthetic-rotated-" + hotkey[:10]
        return 200, {"status": "provisioned", "api_key": self.keys[hotkey], **self.funds[hotkey]}

    async def status(self, hotkey_ss58):
        if hotkey_ss58 not in self.funds:
            return 403, {"status": "ineligible", "reason": "not_provisioned"}
        return 200, {"status": "provisioned", **self.funds[hotkey_ss58]}


@pytest.fixture
def api():
    app = FastAPI()
    worker = SyntheticWorker()
    claim.KubeTEEGammaClaimHandler(worker, authority=claim.MemoryAuthority()).register(app)
    # The only test override: each request is its own distinct agent operation,
    # enabling the parallel join check. Throttling/source checks remain explicit.
    app.state.kubetee_gamma_handler.test_source_ip = app.state.kubetee_gamma_handler.source_ip
    handler = app.state.kubetee_gamma_handler
    def source(request):
        return request.headers.get("x-test-agent", "127.0.0.1") if "x-test-agent" in request.headers else handler.test_source_ip(request)
    app.state.kubetee_gamma_handler.source_ip = source
    return app


async def signed(api, client: AsyncClient, hotkey, action="claim", *, signed=None):
    route = {"claim": "/v1/gamma/key/claim", "regenerate": "/v1/gamma/key/regenerate", "status": "/v1/gamma/status"}
    if signed is None:
        response = await client.post("/v1/gamma/challenge", json={
            "hotkey_ss58": hotkey.ss58_address, "action": action, "netuid": 90,
        })
        assert response.status_code == 200, response.text
        response = response.json()
        signed = {"challenge_id": response["challenge_id"],
                  "signature": hotkey.sign(response["message"].encode()).hex()}
    return await client.post(route[action], json=signed)


@pytest.mark.asyncio
async def test_real_redis_nonce_is_unique_and_challenge_is_atomically_single_use():
    """Native client: real cjson script, NX keys, KEEPTTL and replay rejection."""
    if not os.environ.get("GAMMA_REDIS_TEST_URL"):
        pytest.skip("explicit Redis integration requires GAMMA_REDIS_TEST_URL")
    import hashlib
    import secrets
    from datetime import datetime, timezone
    import redis.asyncio
    client = redis.asyncio.from_url(os.environ["GAMMA_REDIS_TEST_URL"])
    authority = claim.RedisAuthority(client)
    hotkey = new_hotkey()
    nonce = secrets.token_hex(32)
    identifier = secrets.token_hex(16)
    message = "synthetic-exact-hotkey-message"
    now = claim.utc_now()
    entry = {"challenge_id": identifier, "message": message,
             "message_digest": hashlib.sha256(message.encode()).hexdigest(),
             "hotkey_ss58": hotkey.ss58_address, "action": "claim",
             "source_ip": "127.0.0.1", "expires": now.timestamp() + 60,
             "used": False}
    signature = hotkey.sign(message.encode()).hex()
    try:
        assert await authority.insert_nonce(hotkey.ss58_address, nonce, 3600)
        assert not await authority.insert_nonce(hotkey.ss58_address, nonce, 3600)
        nonce_key = "kubetee:gamma:nonce:v1:" + claim._nonce_digest(hotkey.ss58_address, nonce)
        assert 0 < await client.ttl(nonce_key) <= 3600
        await authority.insert_challenge(identifier, {**entry, "expires": datetime.fromtimestamp(entry["expires"], timezone.utc)}, 60)
        assert claim._standard_signature_verified(message, signature, hotkey.ss58_address)
        peer_authority = claim.RedisAuthority(client)
        tasks = [asyncio.create_task(authority.consume(identifier, "claim", signature, "127.0.0.1")),
                 asyncio.create_task(peer_authority.consume(identifier, "claim", signature, "127.0.0.1"))]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        successful = [result for result in results if isinstance(result, dict) and result["used"]]
        rejected = [result for result in results if isinstance(result, claim.HTTPException) and result.status_code == 401]
        assert len(successful) == 1 and len(rejected) == 1, [(type(result), repr(result)) for result in results]
        assert 0 < await client.ttl(authority._key(identifier)) <= 60
        await client.set(authority._key("tampered"), '{"used":false,"message_digest":"wrong","source_ip":"127.0.0.1","action":"claim","expires":9999999999}', ex=60)
        with pytest.raises(claim.HTTPException):
            await authority.consume("tampered", "claim", signature, "127.0.0.1")
    finally:
        for task in locals().get("tasks", []):
            task.cancel()
        await asyncio.gather(*locals().get("tasks", []), return_exceptions=True)
        await client.aclose()


@pytest.mark.asyncio
async def test_native_sentinel_monitor_and_data_identities_are_distinct():
    uri = os.environ.get("GAMMA_REDIS_SENTINEL_TEST_URL")
    if not uri:
        pytest.skip("explicit Sentinel integration requires GAMMA_REDIS_SENTINEL_TEST_URL")
    from kubetee_gamma_transport import native_async_redis, redis_production_settings
    settings = redis_production_settings(uri)
    from urllib.parse import parse_qs, unquote, urlsplit
    service = settings["service_name"]
    client = native_async_redis(settings)
    manager = client.connection_pool.sentinel_manager
    monitor = urlsplit(uri)
    # Expectations come from the supplied URI, never a hard-coded environment:
    # CI's disposable Sentinel and any other target use different DBs.
    options = {name: values[0] for name, values in parse_qs(monitor.query).items()}
    master_before = await manager.discover_master(service)
    try:
        authority = claim.RedisAuthority(client)
        hotkey = new_hotkey()
        nonce = "disposable-nonce-60"
        nonce_key = "kubetee:gamma:nonce:v1:" + claim._nonce_digest(hotkey.ss58_address, nonce)
        assert await authority.insert_nonce(hotkey.ss58_address, nonce, 60)
        assert not await authority.insert_nonce(hotkey.ss58_address, nonce, 60)
        assert await client.ping()
        connection = await client.connection_pool.get_connection()
        try:
            assert (connection.host, connection.port) != (monitor.hostname, monitor.port)
            assert master_before == (connection.host, connection.port)
            data = client.connection_pool.connection_kwargs
            assert client.connection_pool.service_name == service
            assert data["db"] == int(options.get("db", 0))
            assert data["username"] == unquote(monitor.username)
            # The monitor authenticates with its own credential when the URI
            # supplies one; it must not silently inherit the data identity.
            monitor_password = manager.sentinels[0].connection_pool.connection_kwargs["password"]
            assert monitor_password == options.get("sentinel_password", unquote(monitor.password))
            assert await manager.discover_master(service) == master_before
        finally:
            await client.connection_pool.release(connection)
    finally:
        if "client" in locals() and "nonce_key" in locals():
            await client.delete(nonce_key)
        await client.aclose()
        for monitor_client in manager.sentinels:
            await monitor_client.aclose()
    # No FLUSHDB, monitor/data rewrite, or master-state change on staging.


@pytest.mark.asyncio
async def test_exact_h_wrong_h_amount_replay_expiry_and_throttle(api):
    hotkey, wrong = new_hotkey(), new_hotkey()
    async with AsyncClient(transport=ASGITransport(app=api), base_url="http://test", headers={"x-test-agent": "negative"}) as client:
        assert (await client.post("/v1/gamma/challenge", json=None)).status_code == 422
        assert (await client.post("/v1/gamma/status", json=None)).status_code == 401
        assert (await client.post("/v1/gamma/status", json={"hotkey_ss58": hotkey.ss58_address})).status_code == 401
        challenge_response = await client.post("/v1/gamma/challenge", json={
            "hotkey_ss58": hotkey.ss58_address, "action": "claim", "netuid": 90,
        })
        assert challenge_response.status_code == 200
        challenge_response = challenge_response.json()
        payload = {"challenge_id": challenge_response["challenge_id"],
                   "signature": hotkey.sign(challenge_response["message"].encode()).hex()}
        message = json.loads(challenge_response["message"])
        assert message["hotkey_ss58"] == message["signer_ss58"] == hotkey.ss58_address
        assert message["network"] == "finney"
        assert message["action"] == "claim"
        assert (await client.post("/v1/gamma/key/claim", json={**payload, "amount": 99})).status_code == 422
        assert (await client.post("/v1/gamma/key/claim", json={
            **payload, "signature": wrong.sign(challenge_response["message"].encode()).hex(),
        })).status_code == 403
        expired = await client.post("/v1/gamma/challenge", json={
            "hotkey_ss58": wrong.ss58_address, "action": "claim", "netuid": 90,
        })
        assert expired.status_code == 200
        expired = expired.json()
        api.state.kubetee_gamma_handler.authority.entries[expired["challenge_id"]]["expires"] = claim.utc_now()
        assert (await client.post("/v1/gamma/key/claim", json={
            "challenge_id": expired["challenge_id"], "signature": wrong.sign(expired["message"].encode()).hex(),
        })).status_code == 401
        assert (await client.post("/v1/gamma/challenge", json={
            "hotkey_ss58": hotkey.ss58_address, "action": "claim", "netuid": 90,
        })).status_code == 429


@pytest.mark.asyncio
async def test_bounded_pending_then_funded_key_and_no_double_reconcile(api):
    hotkey = new_hotkey()
    async with AsyncClient(transport=ASGITransport(app=api), base_url="http://test") as client:
        result = await signed(api, client, hotkey)
        assert result.status_code == 202
        assert "api_key" not in result.text and result.headers["Retry-After"] == "6"
        current = api.state.kubetee_gamma_handler.source_ip
        api.state.kubetee_gamma_handler.source_ip = lambda r: "retry"
        result = replay = await client.post("/v1/gamma/key/claim", content=result.request.content,
                                   headers={"Content-Type": "application/json"})
        assert replay.status_code == 401


@pytest.mark.asyncio
async def test_three_concurrent_fresh_claims_join_one_key_and_credit(api):
    hotkey = new_hotkey()
    api.state.kubetee_gamma_worker.responses = []
    async with AsyncClient(transport=ASGITransport(app=api), base_url="http://test") as client:
        results = await asyncio.gather(*(
            signed(api, client, hotkey) if i == 0 else signed(api, AsyncClient(transport=ASGITransport(app=api), base_url="http://test", headers={"x-test-agent": f"parallel-{i}"}), hotkey)
            for i in range(3)))

        assert all(result.status_code == 200 for result in results)
        assert len({result.json()["api_key"] for result in results}) == 1
        assert api.state.kubetee_gamma_worker.max_concurrent == 1
        assert api.state.kubetee_gamma_worker.funds[hotkey.ss58_address]["max_budget"] == "2"


@pytest.mark.asyncio
async def test_signed_credit_status_and_rotation(api):
    hotkey, wrong = new_hotkey(), new_hotkey()
    api.state.kubetee_gamma_worker.responses = []
    async with AsyncClient(transport=ASGITransport(app=api), base_url="http://test") as client:
        issued = await signed(api, client, hotkey)
        assert issued.status_code == 200
        current = api.state.kubetee_gamma_handler.source_ip
        api.state.kubetee_gamma_handler.source_ip = lambda r: "status"
        status = await signed(api, client, hotkey, "status")
        api.state.kubetee_gamma_handler.source_ip = current
        assert status.status_code == 200
        assert status.json()["spend"] == "0"
        assert status.json()["max_budget"] == status.json()["remaining_credit"] == "2"
        assert not any(field in status.text for field in ("api_key", "token", "key_alias"))
        api.state.kubetee_gamma_handler.challenge_limit.values.clear()
        api.state.kubetee_gamma_handler.signed_limit.values.clear()
        rotated = await signed(api, client, hotkey, "regenerate")
        assert rotated.status_code == 200
        assert rotated.json()["remaining_credit"] == "2"
        assert rotated.json()["api_key"] != issued.json()["api_key"]
        api.state.kubetee_gamma_worker.responses = []
        current = api.state.kubetee_gamma_handler.source_ip
        api.state.kubetee_gamma_handler.source_ip = lambda r: "other-agent"
        assert (await signed(api, client, wrong, "regenerate")).status_code == 403
        api.state.kubetee_gamma_handler.source_ip = current


@pytest.mark.asyncio
async def test_invalid_funded_result_cannot_disclose_an_empty_key(api):
    async def invalid(_):
        return 200, {"status": "provisioned", "api_key": "sk-unfunded-should-not-leak",
                     "max_budget": 0, "spend": 0, "remaining_credit": 0,
                     "has_positive_chain_settlement": True, "reconciliation_reference": "bad"}
    api.state.kubetee_gamma_worker.claim = invalid
    async with AsyncClient(transport=ASGITransport(app=api), base_url="http://test") as client:
        result = await signed(api, client, new_hotkey())
        assert result.status_code == 503
        assert "sk-unfunded" not in result.text


def test_synthetic_cli_signature_matches_builtin_public_verifier(tmp_path):
    wallet = bt.Wallet("synthetic-pilot", "gamma-pilot", str(tmp_path))
    wallet.create_new_coldkey(use_password=False, crypto_type=bt.CRYPTO_SR25519, suppress=True)
    wallet.create_new_hotkey(use_password=False, crypto_type=bt.CRYPTO_SR25519, suppress=True)
    assert wallet.hotkey.crypto_type == bt.CRYPTO_SR25519
    message = '{"scheme":"kubetee-gamma-challenge/v1","pilot":"synthetic"}'
    btcli = shutil.which("btcli")
    assert btcli, "External signer contract requires the documented btcli binary on PATH"
    result = subprocess.run([
        btcli, "wallet", "sign", "--message", message, "--use-hotkey", "-w", "synthetic-pilot",
        "-H", "gamma-pilot", "--wallet-path", str(tmp_path), "--json",
    ], env={**os.environ, "BT_NO_CRT_SHIM": "1"}, capture_output=True, text=True, check=True)
    response = json.loads(result.stdout)
    signature = response["signed_message"]
    assert response["signer_address"] == wallet.hotkey.ss58_address
    assert len(signature) == 128
    assert claim._verify(message, signature, wallet.hotkey.ss58_address)
    assert not claim._verify(message + " ", signature, wallet.hotkey.ss58_address)
    assert not claim._verify(message, signature, new_hotkey().ss58_address)


def test_separate_worker_pending_translates_to_public_bounded_wait():
    response = Response(200, json={
        "status": "pending", "reason": "spend_final_credit_pending",
        "retry_after_seconds": 6, "correlation_id": None,
    })
    from kubetee_gamma_private_mtls import InProcessIssueClient
    from test_kubetee_gamma_management import SyntheticStore
    import kubetee_gamma_management as mg
    service = mg.GammaManagement(proxy=SyntheticStore(), models=["m"],
                                 certificate_fingerprint="a" * 64)
    transport = claim.PrivateWorkerResponse(object(), InProcessIssueClient(service))
    assert transport._result(response) == (202, response.json())
    code, result = transport._result(response)
    projected = claim._typed_response(code, result)
    assert projected.status_code == 202
    assert json.loads(projected.body) == {
        "status": "pending", "reason": "spend_final_credit_pending",
        "retry_after_seconds": 6, "correlation_id": "",
    }

def test_proxy_and_management_enablement_boundaries():
    worker = SyntheticWorker()
    worker.trusted_proxy_ips = ("10.0.0.1",)
    with pytest.raises(ValueError):
        claim.KubeTEEGammaClaimHandler(worker)
    with pytest.raises(RuntimeError):
        claim.KubeTEEGammaClaimHandler(claim.UnavailableWorker(), authority=claim.MemoryAuthority()).register(FastAPI())
    handler = claim.KubeTEEGammaClaimHandler(SyntheticWorker())
    scope = {"type": "http", "method": "POST", "path": "/v1/gamma/challenge", "query_string": b"", "headers": [(b"x-forwarded-for", b"garbage")], "client": ("127.0.0.1", 123)}
    assert handler.source_ip(Request(scope)) == "127.0.0.1"
    handler.worker.trusted_proxy_ips = ("127.0.0.1",)
    assert handler.source_ip(Request(scope)) == "127.0.0.1"
    scope["headers"] = [(b"x-forwarded-for", b"192.0.2.10, 10.0.0.1")]
    assert handler.source_ip(Request(scope)) == "192.0.2.10"
