"""Private Gamma native key API and worker HTTP contracts; all fixtures synthetic."""
from __future__ import annotations

import asyncio
from base64 import b64decode
import base64
import copy
import hashlib
import importlib.util
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio

# Lease fencing mutex applies to native row transitions, including zero reservations.

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from unittest import mock

ROOT = Path(__file__).resolve().parents[4]
import os
SUBNET = Path(os.environ.get(
    "KUBETEE_GAMMA_WORKER_ROOT",
    ROOT.parent.parent / "kubetee-subnet/gamma-funder-release/gamma_funder",
)).resolve()
assert (SUBNET / "tests/fixtures.py").is_file(), "untrusted/incomplete worker source fixture"
sys.path.insert(0, str(ROOT / "tools/kubetee-litellm-overlay"))
sys.path.insert(0, str(SUBNET))
import kubetee_gamma_management as mg
from kubetee_gamma_claim import validate_claimed_result, PrivateWorkerResponse, KubeTEEGammaClaimHandler, MemoryAuthority
from worker.management import Management, StateConflict
from worker.protocol import settlement_reference

_fixture_spec = importlib.util.spec_from_file_location("gamma_fixtures", SUBNET / "tests/fixtures.py")
fixtures = importlib.util.module_from_spec(_fixture_spec)
sys.modules[_fixture_spec.name] = fixtures
_fixture_spec.loader.exec_module(fixtures)
HK, COLD = fixtures.HK, fixtures.COLD
SyntheticChain = fixtures.SyntheticChain
SECRET = "sk-synthetic-owned-secret-long"
ROTATED = "sk-synthetic-rotated-owned-secret"


def cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic worker")])
    now = datetime.now(timezone.utc)
    certificate = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(
        x509.random_serial_number()).not_valid_before(now).not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256())
    der = certificate.public_bytes(serialization.Encoding.DER)
    return base64.b64encode(der).decode(), hashlib.sha256(der).hexdigest()


def fresh_checkpoint():
    return {"schema": 1, "network": "finney", "genesis_hash": mg.GENESIS, "netuid": 90,
        "observation_height": 1, "observation_hash": "0x" + "1" * 64,
        "observation_coldkey": COLD, "observation_spender": "service-spender",
        "accepted_kind": "minted_pending", "delta_units": 0, "previous_units": 0,
        "receipt_ids": [], "total_settled_units": 0, "pending": None,
        "last_spent_height": None, "last_spent_amount": None, "last_spent_reference": None,
        "cap": None, "needs_cap_audit": False}


def settlement_intent(amount=1_000_000_000, height=10):
    planning_hash = f"0x{height:064x}"
    pending_ref = {"block_number": height, "block_hash": planning_hash, "event_index": -1,
        "hotkey_ss58": HK, "netuid": 90, "amount_units": amount,
        "reference": settlement_reference(90, HK, planning_hash, amount)}
    cp = fresh_checkpoint()
    cp["delta_units"] = amount
    cp["pending"] = {"reference": pending_ref, "intake_height": height,
                     "planning_hash": planning_hash, "attempts": 1,
                     "parent_units": amount, "expected_checkpoint": {**cp, "pending": None}}
    settlement = mg.ProvenanceSettlement.from_settlement(
        {**pending_ref, "block_number": height + 1, "event_index": 2,
         "block_hash": f"0x{height + 1:064x}"}, planning_hash)
    return cp, settlement


def settled_checkpoint(cp, s):
    next_cp = copy.deepcopy(cp)
    next_cp.update({"pending": None, "delta_units": 0,
        "observation_height": s.block_number, "observation_hash": s.block_hash,
        "last_spent_height": s.block_number, "last_spent_amount": s.amount_units,
        "last_spent_reference": s.reference,
        "total_settled_units": cp["total_settled_units"] + s.amount_units,
        "receipt_ids": [*cp["receipt_ids"], s.model_dump(exclude={"observation_hash"})]})
    return next_cp


def top_up_intent(settled, amount, height):
    """A later mint on an already-settled key: (observed, pending intent, settlement)."""
    planning_hash = f"0x{height:064x}"
    pending_ref = {"block_number": height, "block_hash": planning_hash, "event_index": -1,
        "hotkey_ss58": HK, "netuid": 90, "amount_units": amount,
        "reference": settlement_reference(90, HK, planning_hash, amount)}
    observed = {**copy.deepcopy(settled), "delta_units": amount, "pending": None}
    intent = {**copy.deepcopy(observed), "pending": {"reference": pending_ref,
        "intake_height": height, "planning_hash": planning_hash, "attempts": 1,
        "parent_units": amount, "expected_checkpoint": copy.deepcopy(observed)}}
    settlement = mg.ProvenanceSettlement.from_settlement(
        {**pending_ref, "block_number": height + 1, "event_index": 2,
         "block_hash": f"0x{height + 1:064x}"}, planning_hash)
    return observed, intent, settlement


def scope(store, **fields):
    return {"network": "finney", "genesis_hash": mg.GENESIS, "netuid": 90,
            "hotkey_ss58": HK, "token_id": store.row.token, **fields}


class SyntheticStore:
    def __init__(self):
        self.row = None
        self.secret = SECRET
        self.credit_writes = 0
        self.rotations = 0

    async def find_exact_hotkey(self, hotkey):
        assert hotkey == HK
        return self.row

    async def gamma_identities(self):
        if self.row is None:
            return []
        return [{"metadata": {"gamma": json.loads(self.row.metadata)["gamma"]}}]

    async def reserve(self, hotkey, checkpoint, permissions, secret):
        assert hotkey == HK
        if self.row is not None:
            raise mg.ManagingConflict("already reserved")
        self.row = SimpleNamespace(
            token=hashlib.sha256(secret.encode()).hexdigest(),
            key_alias=COLD + "-" + HK.lower(), metadata=json.dumps({"gamma_hotkey": HK, "gamma_netuid": 90,
                "gamma_network": "finney", "gamma": checkpoint}),
            updated_at=datetime.now(timezone.utc), max_budget="0", spend="0",
            blocked=True, models=permissions["models"], team_id=None,
            object_permission={"mcp_servers": permissions["mcp_servers"]})
        self.secret = secret
        return self.row

    async def compare_checkpoint(self, hotkey, expected, checkpoint, expected_max_budget,
                                 *, target_max_budget=None):
        await asyncio.sleep(0)
        md = json.loads(self.row.metadata)
        # Native spend is deliberately not part of the precondition.
        if (hotkey != HK or md["gamma"] != expected
                or Decimal(self.row.max_budget) != Decimal(expected_max_budget)):
            raise mg.ManagingConflict("stale native row")
        md["gamma"] = checkpoint
        self.row.metadata = json.dumps(md)
        self.row.updated_at = datetime.now(timezone.utc)
        if target_max_budget is not None:
            self.row.max_budget = target_max_budget
            if not expected.get("total_settled_units"):
                self.row.blocked = False  # first credit enables in the same write
            self.credit_writes += 1
        return self.row

    async def compare_and_checkpoint(self, hotkey, expected, checkpoint, previous_max_budget,
                                     target_max_budget):
        return await self.compare_checkpoint(hotkey, expected, checkpoint, previous_max_budget,
                                             target_max_budget=target_max_budget)

    async def stored_key(self, row):
        return self.secret if row.token == hashlib.sha256(self.secret.encode()).hexdigest() else None

    async def update(self, row, **changes):
        assert row.token == self.row.token
        if "metadata" in changes:
            self.row.metadata = json.dumps(changes["metadata"])
        if "max_budget" in changes:
            self.credit_writes += 1
        self.row.max_budget = changes.get("max_budget", self.row.max_budget)
        self.row.blocked = changes.get("blocked", self.row.blocked)
        return self.row

    async def evict(self, token):
        assert isinstance(token, str) and len(token) == 64

    async def rotate(self, hotkey):
        assert hotkey == HK
        self.rotations += 1
        self.secret = ROTATED
        self.row.token = hashlib.sha256(ROTATED.encode()).hexdigest()
        return self.row, ROTATED

    async def table(self):
        store = self
        class Table:
            async def update(self, *, where, data):
                raise RuntimeError("native update must be routed through the Management API")
                return store.row
        return Table()


@pytest.fixture
def worker_identity():
    return cert()


def app(store, identity):
    certificate, fingerprint = identity
    service = mg.GammaManagement(proxy=store, models=["selected-model"], mcp_servers=None,
                                 certificate_fingerprint=fingerprint, proxy_ip="127.0.0.1")
    import kubetee_gamma_private_mtls as private
    return private.create_private_application(service)


def management(store, identity, lease=None):
    certificate, _ = identity
    private_app = app(store, identity)
    private_management = private_app.state.kubetee_gamma_private_management
    private_management.issuance_lease = lease
    class VerifiedSocket:
        def get_extra_info(self, name):
            assert name == "ssl_object"
            return self
        def getpeercert(self, binary_form):
            assert binary_form is True
            return b64decode(certificate.replace("\n", ""), validate=True)
    asgi = ASGITransport(app=private_app, client=("127.0.0.1", 1234))
    class SocketTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            original_app = asgi.app
            async def scoped(scope, receive, send):
                scope.setdefault("extensions", {})["transport"] = VerifiedSocket()
                await original_app(scope, receive, send)
            asgi.app = scoped
            return await asgi.handle_async_request(request)
    transport = SocketTransport()
    http = AsyncClient(transport=transport, headers={"x-kubetee-worker-cert-der": "forged"})
    return private_management, http


@pytest.mark.asyncio
@pytest.mark.asyncio
async def test_native_management_requires_authenticated_team_service_identity(monkeypatch):
    from litellm.proxy._types import UserAPIKeyAuth
    native = object.__new__(mg.NativeKeys)
    authenticated = UserAPIKeyAuth(token="0" * 64, user_id="gamma@kubetee.ai",
        team_id="00000000-0000-4000-8000-000000000090", user_role="internal_user")
    calls = []
    async def authenticate(request):
        calls.append(request.headers["authorization"])
        return authenticated
    monkeypatch.setattr("litellm.proxy.auth.user_api_key_auth.user_api_key_auth", authenticate)
    with mock.patch.dict(os.environ, {
        "KUBETEE_GAMMA_TEAM_MANAGEMENT_KEY": "sk-synthetic-management-context-only",
        "KUBETEE_GAMMA_USER_ID": "gamma@kubetee.ai",
        "KUBETEE_GAMMA_TEAM_ID": "00000000-0000-4000-8000-000000000090",
    }):
        assert await native.admin() is authenticated
        authenticated = UserAPIKeyAuth(token="1" * 64, user_id="gamma@kubetee.ai",
            team_id="00000000-0000-4000-8000-000000000090", user_role="internal_user")
        authenticated.team_id = "different-team"
        with pytest.raises(mg.ManagingConflict):
            await native.admin()
        assert calls == ["Bearer sk-synthetic-management-context-only"] * 2


@pytest.mark.asyncio
async def test_native_serialized_index_and_no_external_issue_endpoint(worker_identity):
    store = SyntheticStore()
    await store.reserve(HK, fresh_checkpoint(), {"models": ["m"], "mcp_servers": None}, SECRET)
    _, http = management(store, worker_identity)
    async with http:
        result = await http.get("http://gateway/internal/v1/gamma/keys")
        assert result.status_code == 200 and result.json()["keys"][0]["metadata"]["gamma"]["observation_coldkey"] == COLD
        # The measured worker only supplies a verified context to the gateway's
        # in-process callback; external issuance can never substitute a digest.
        issue = await http.post("http://gateway/internal/v1/gamma/key/issue", json={
            "network": "finney", "genesis_hash": mg.GENESIS, "netuid": 90,
            "hotkey_ss58": HK, "action": "claim", "verification_digest": "a" * 64})
        assert issue.status_code == 404


@pytest.mark.asyncio
async def test_native_regenerate_routes_api_and_checks_hash_id_and_stored_secret(monkeypatch):
    from litellm.proxy._types import GenerateKeyResponse
    # v1.108.3 puts hash_token(new_token) in BOTH token_id and the remapped
    # token field. It has no query_result/opaque database id field.
    opaque = "native-database-id-not-in-response"
    new_sha = hashlib.sha256(ROTATED.encode()).hexdigest()
    assert opaque != new_sha
    row = SimpleNamespace(token="0" * 64, key_alias=COLD + "-" + HK.lower(), metadata={"gamma_hotkey": HK})
    replaced = SimpleNamespace(token=new_sha, key_alias=row.key_alias, metadata=row.metadata)
    native = object.__new__(mg.NativeKeys)
    calls = []
    from litellm.proxy.management_endpoints import key_management_endpoints as native_api
    async def regenerate(**kwargs):
        calls.append(kwargs)
        assert kwargs["data"].key_alias == row.key_alias
        return GenerateKeyResponse.model_validate({
            "token": new_sha, "token_id": new_sha, "key": ROTATED,
            "metadata": row.metadata, "max_budget": 1,
        })
    monkeypatch.setattr(native_api, "regenerate_key_fn", regenerate)
    from unittest.mock import AsyncMock
    monkeypatch.setattr(mg.NativeKeys, "admin", AsyncMock(return_value=None))
    async def readback(self, hotkey):
        return replaced if calls else row
    monkeypatch.setattr(mg.NativeKeys, "find_exact_hotkey", readback)
    monkeypatch.setattr(mg.NativeKeys, "stored_key", AsyncMock(return_value=ROTATED))
    current, returned = await native.rotate(HK)
    assert current is replaced and returned == ROTATED
    assert len(calls) == 1 and calls[0]["key"] == row.token
    with monkeypatch.context() as different:
        different.setattr(mg.NativeKeys, "stored_key", AsyncMock(return_value="sk-wrong"))
        with pytest.raises(mg.ManagingConflict, match="stored key"):
            await native.rotate(HK)


@pytest.mark.asyncio
async def test_issue_rechecks_finalized_checkpoint_identity(worker_identity):
    store = SyntheticStore()
    await store.reserve(HK, fresh_checkpoint(), {"models": ["m"], "mcp_servers": None}, SECRET)
    data = json.loads(store.row.metadata)
    data["gamma"]["total_settled_units"] = 1
    data["gamma"]["last_spent_reference"] = "a" * 64
    store.row.max_budget = "1"
    store.row.blocked = False
    store.row.metadata = json.dumps(data)
    service = mg.GammaManagement(proxy=store, models=["m"], certificate_fingerprint="3" * 64)
    result = await service.issue(HK, "claim", "a" * 64)
    assert result["status"] == "provisioned"
    data["gamma"]["hotkey_ss58"] = "5" * 48
    store.row.metadata = json.dumps(data)
    with pytest.raises(mg.ManagingConflict, match="wrong exact-H"):
        await service.issue(HK, "claim", "a" * 64)


@pytest.mark.asyncio
async def test_mtls_fingerprint_and_proxy_are_required(worker_identity):
    certificate, fingerprint = worker_identity
    store = SyntheticStore()
    async with AsyncClient(transport=ASGITransport(app=app(store, worker_identity), client=("10.1.2.3", 1)),
                           headers={"x-kubetee-worker-cert-der": "not-der"}, base_url="https://invalid") as client:
        assert (await client.get("/internal/v1/gamma/key", params={"hotkey_ss58": HK, "network": "finney", "genesis_hash": mg.GENESIS, "netuid": "90"})).status_code == 403
    service = mg.GammaManagement(proxy=store, models=["m"], certificate_fingerprint=fingerprint)
    with pytest.raises(mg.HTTPException):
        service.validate_worker_auth("10.1.2.3", None)
    with pytest.raises(mg.HTTPException):
        service.validate_worker_cert("bad")
    with pytest.raises(mg.HTTPException):
        mg.GammaManagement(proxy=store, models=["m"], certificate_fingerprint="0" * 64).validate_worker_cert(certificate)


def test_signed_challenge_digest_must_match_signed_message_identity():
    cp, settlement = settlement_intent()
    with pytest.raises(ValueError):
        mg.ProvenanceSettlement.model_validate({**settlement.model_dump(), "amount_units": 2_000_000_000})
    with pytest.raises(ValueError):
        validate_claimed_result({"status": "provisioned", "api_key": SECRET, "max_budget": "1",
            "spend": "0", "remaining_credit": "1", "has_positive_chain_settlement": True,
            "reconciliation_reference": settlement.reference}, "claim")


@pytest.mark.asyncio
async def test_checkpoint_read_before_and_after_credit_with_replay_rejection(worker_identity):
    store = SyntheticStore()
    service, http = management(store, worker_identity)
    worker = Management(http, "https://internal.invalid", "narrow worker credential")
    async with http:
        assert await worker.info(HK) is None
        cp, settlement = settlement_intent()
        row = await worker.reserve(HK, cp["pending"]["expected_checkpoint"])
        assert row["key_alias"] == COLD + "-" + HK.lower() and Decimal(row["max_budget"]) == 0
        row = await worker.conditional_transition(HK, row, cp)
        result = await worker.credit_and_checkpoint(HK, row, settlement, settlement.amount_units, settled_checkpoint(cp, settlement))
        assert Decimal(result["spend"]) == 0
        assert Decimal(result["max_budget"]) == 1
        with pytest.raises(StateConflict):
            await worker.credit_and_checkpoint(HK, row, settlement,
                2 * settlement.amount_units, settled_checkpoint(cp, settlement))
        with pytest.raises(StateConflict):
            await worker.conditional_transition(HK, result, {**cp, "invalid": True})


@pytest.mark.asyncio
async def test_concurrent_credit_and_pending_intent_only_advance_once(worker_identity):
    store = SyntheticStore()
    cp, settlement = settlement_intent()
    await store.reserve(HK, cp, {"models": ["m"], "mcp_servers": None}, SECRET)
    service, http = management(store, worker_identity)
    worker = Management(http, "https://internal.invalid", "narrow worker credential")
    async with http:
        row = await worker.info(HK)
        calls = await asyncio.gather(
            worker.credit_and_checkpoint(HK, row, settlement, settlement.amount_units, settled_checkpoint(cp, settlement)),
            worker.credit_and_checkpoint(HK, row, settlement, settlement.amount_units, settled_checkpoint(cp, settlement)),
            return_exceptions=True)
        assert [isinstance(result, Exception) for result in calls].count(False) == 1
        assert all(isinstance(result, StateConflict) for result in calls if isinstance(result, Exception))
    assert store.credit_writes == 1


@pytest.mark.asyncio
async def test_redis_fence_excludes_second_replica_and_withholds_lost_credentials(worker_identity, redis_lease):
    store = SyntheticStore()
    cp, settlement = settlement_intent()
    await store.reserve(HK, cp, {"models": ["m"], "mcp_servers": None}, SECRET)
    await store.compare_checkpoint(HK, cp, settled_checkpoint(cp, settlement), "0", target_max_budget="1")
    native, native_http = management(store, worker_identity, lease=redis_lease)
    caller, caller_http = management(store, worker_identity, lease=redis_lease)
    rotating = asyncio.Event()
    complete = asyncio.Event()

    async def interlocked_rotation(hotkey):
        rotating.set()
        await complete.wait()
        await asyncio.sleep(.25)
        store.rotations += 1
        store.secret = ROTATED
        store.row.token = hashlib.sha256(ROTATED.encode()).hexdigest()
        return store.row, ROTATED

    original_rotate = store.rotate
    store.rotate = interlocked_rotation
    first = second = None
    try:
        # This is deliberately the same native async Redis client as production;
    # distinct event-loop ownership is tested by the function-scoped fixture.
        lease_waited = asyncio.Event()
        original_set = redis_lease.set
        async def observed_acquire(*args, **kwargs):
            result = await original_set(*args, **kwargs)
            if result is not True:
                lease_waited.set()
            return result
        caller.issuance_lease.set = observed_acquire
        # Real native GammaManagement service on both replicas, sharing only Redis.
        first = asyncio.create_task(native.issue(HK, "regenerate", "a" * 64))
        started = asyncio.create_task(rotating.wait())
        ready, _ = await asyncio.wait({first, started}, timeout=5,
                                      return_when=asyncio.FIRST_COMPLETED)
        if first in ready:
            await first
        assert started in ready, "rotation never reached the cross-replica interlock"
        await started
        second = asyncio.create_task(mg.GammaManagement.issue(caller, HK, "claim", "b" * 64))
        await asyncio.wait_for(lease_waited.wait(), 5)
        assert not second.done(), "second gateway instance bypassed its Redis lease"
        complete.set()
        assert (await first)["api_key"] == ROTATED
        recovered = await second
        assert recovered["api_key"] == ROTATED
        assert store.rotations == 1, "claim used the stale credential after a true lease race"
    finally:
        complete.set()
        if first is not None:
            await asyncio.gather(first, return_exceptions=True)
        if second is not None:
            await asyncio.gather(second, return_exceptions=True)
        store.rotate = original_rotate
        await native_http.aclose()
        await caller_http.aclose()


@pytest.mark.asyncio
async def test_lost_issuance_lease_never_discloses_a_rotated_secret(worker_identity, redis_lease):
    store = SyntheticStore()
    cp, settlement = settlement_intent()
    await store.reserve(HK, cp, {"models": ["m"], "mcp_servers": None}, SECRET)
    await store.compare_checkpoint(HK, cp, settled_checkpoint(cp, settlement), "0", target_max_budget="1")
    service, http = management(store, worker_identity, lease=redis_lease)
    lock_key = "kubetee:gamma:key-issue-lease:v1:" + HK
    rotated = asyncio.Event()
    original_rotate = store.rotate
    first = None
    try:
        def lost_owner(**kwargs):
            return 0
        lost_owner.__module__ = mg.__name__ + ".redis_fencing"
        service.release_script = lost_owner
        service.owner_script = lost_owner
        async def release_after_lost_owner(**kwargs):
            # The lost holder releases its token AFTER their successor acquires;
            # only token-comparing Lua deletion preserves the successor fence.
            await redis_lease.set(lock_key, "successor-token", nx=True, ex=60)
            return await redis_lease.eval(
                "if redis.call('GET',KEYS[1]) == ARGV[1] then return redis.call('DEL',KEYS[1]) else return 0 end",
                1, lock_key, kwargs["args"][0])
        redis_lease.register_script = lambda script: release_after_lost_owner
        async def pause_rotation(hotkey):
            await rotated.wait()
            return await original_rotate(hotkey)
        store.rotate = pause_rotation
        first = asyncio.create_task(service.issue(HK, "regenerate", "a" * 64))
        await asyncio.sleep(.1)
        assert await redis_lease.exists(lock_key)
        await redis_lease.delete(lock_key)
        rotated.set()
        with pytest.raises(mg.HTTPException) as failed:
            await first
        assert failed.value.status_code == 503, failed.value
        assert ROTATED not in str(failed.value.detail)
        assert store.rotations == 1
        # A leader who has timed out must not drop the next holder's lease.
        successor = await redis_lease.get(lock_key)
        if isinstance(successor, bytes):
            successor = successor.decode("ascii")
        assert successor == "successor-token"
        assert store.secret == ROTATED
    finally:
        rotated.set()
        if first is not None:
            await asyncio.gather(first, return_exceptions=True)
        store.rotate = original_rotate
        await http.aclose()


@pytest_asyncio.fixture(loop_scope="function")
async def redis_lease():
    """Explicit staging URL, test DB 15; no shared customer-key flush."""
    if not os.environ.get("GAMMA_REDIS_TEST_URL"):
        pytest.skip("explicit Redis integration requires GAMMA_REDIS_TEST_URL")
    import redis.asyncio
    client = redis.asyncio.from_url(os.environ["GAMMA_REDIS_TEST_URL"])
    from urllib.parse import urlsplit
    if urlsplit(os.environ["GAMMA_REDIS_TEST_URL"]).path != "/15":
        pytest.skip("real Redis integration is restricted to test database /15")
    prefix = "kubetee:gamma:key-issue-lease:v1:" + HK
    found = []
    try:
        yield client
    finally:
        async for key in client.scan_iter(match=prefix, count=16):
            await client.delete(key)
            found.append(key)
        assert len(found) <= 2
        assert client.connection_pool.connection_kwargs["db"] == 15
        await client.aclose()


@pytest.mark.asyncio
async def test_pending_transition_is_a_read_conflict_not_stale_reservation(worker_identity):
    store = SyntheticStore()
    cp, _ = settlement_intent()
    await store.reserve(HK, cp, {"models": ["m"], "mcp_servers": None}, SECRET)
    service = mg.GammaManagement(proxy=store, models=["m"], certificate_fingerprint="3" * 64)
    with pytest.raises(mg.ManagingConflict):
        await service.checkpoint(mg.CheckpointRequest(network="finney", genesis_hash=mg.GENESIS,
            netuid=90, hotkey_ss58=HK, token_id=store.row.token,
            previous_max_budget="0", previous_spend="0",
            expected_checkpoint=cp, checkpoint={**cp, "state": "second-attempt"}))


@pytest.mark.asyncio
async def test_issue_only_after_proven_credit_and_repeat_does_not_rotate(worker_identity):
    store = SyntheticStore()
    service = mg.GammaManagement(proxy=store, models=["m"], certificate_fingerprint="3" * 64)
    with pytest.raises(mg.HTTPException) as error:
        await service.issue(HK, "claim", "a" * 64)
    assert error.value.status_code == 409
    cp, settlement = settlement_intent()
    await store.reserve(HK, cp, {"models": ["m"], "mcp_servers": None}, SECRET)
    with pytest.raises(mg.HTTPException):
        await service.issue(HK, "claim", "a" * 64)
    await service.credit(mg.CreditRequest(network="finney", genesis_hash=mg.GENESIS, netuid=90,
        hotkey_ss58=HK, token_id=store.row.token, previous_max_budget="0", previous_spend="0",
        previous_checkpoint=cp, expected_checkpoint=settled_checkpoint(cp, settlement),
        settlement=settlement, target_max_budget="1", amount_units=settlement.amount_units))
    # The credit itself enabled the reserved key; delivery writes nothing.
    assert store.row.blocked is False
    updates = []
    original_update = store.update
    async def recorded_update(row, **changes):
        updates.append(changes)
        return await original_update(row, **changes)
    store.update = recorded_update
    first = await service.issue(HK, "claim", "a" * 64)
    assert updates == []
    assert first["status"] == "provisioned" and first["has_positive_chain_settlement"] is True
    assert first["remaining_credit"] == "1"
    assert validate_claimed_result(first, True)["api_key"] == SECRET
    assert (await service.issue(HK, "claim", "b" * 64))["api_key"] == SECRET
    assert store.credit_writes == 1 and store.rotations == 0
    assert (await service.issue(HK, "regenerate", "c" * 64))["api_key"] == ROTATED
    assert store.rotations == 1 and store.row.blocked is False
    assert Decimal(store.row.max_budget) == 1 and Decimal(store.row.spend) == 0


@pytest.mark.asyncio
async def test_top_up_ignores_native_spend_and_budget_stays_the_settled_total():
    store = SyntheticStore()
    service = mg.GammaManagement(proxy=store, models=["m"], certificate_fingerprint="3" * 64)
    cp, first = settlement_intent()
    await store.reserve(HK, cp, {"models": ["m"], "mcp_servers": None}, SECRET)
    settled = settled_checkpoint(cp, first)
    await service.credit(mg.CreditRequest(**scope(store, previous_max_budget="0",
        previous_checkpoint=cp, expected_checkpoint=settled, settlement=first,
        target_max_budget="1", amount_units=first.amount_units)))
    # The key is in service: usage is a moving float, not 1e-9 Gamma units.
    store.row.spend = 0.30000000000000004
    observed, intent, second = top_up_intent(settled, 500_000_000, 20)
    await service.checkpoint(mg.CheckpointRequest(**scope(store, previous_max_budget="1",
        expected_checkpoint=settled, checkpoint=observed)))
    await service.checkpoint(mg.CheckpointRequest(**scope(store, previous_max_budget="1",
        previous_spend="0", expected_checkpoint=observed, checkpoint=intent)))
    store.row.spend = 0.7000000000000001  # moved again between read and credit
    topped = settled_checkpoint(intent, second)
    assert topped["total_settled_units"] == 1_500_000_000
    result = await service.credit(mg.CreditRequest(**scope(store, previous_max_budget="1",
        previous_spend="0.30000000000000004", previous_checkpoint=intent,
        expected_checkpoint=topped, settlement=second, target_max_budget="1.5",
        amount_units=second.amount_units)))
    assert Decimal(result["row"]["max_budget"]) == Decimal("1.5")
    assert mg.settled_total(json.loads(store.row.metadata)["gamma"]) == mg.exact_units(store.row.max_budget)
    assert store.credit_writes == 2 and store.row.spend == 0.7000000000000001
    issued = await service.issue(HK, "claim", "a" * 64)
    assert issued["max_budget"] == "1.5" and issued["spend"] == "0.7000000000000001"
    assert Decimal(issued["remaining_credit"]) == Decimal("0.7999999999999999")
    assert validate_claimed_result(issued, True)["api_key"] == SECRET


@pytest.mark.asyncio
async def test_credit_refuses_any_budget_that_is_not_the_settled_total():
    store = SyntheticStore()
    service = mg.GammaManagement(proxy=store, models=["m"], certificate_fingerprint="3" * 64)
    cp, first = settlement_intent()
    await store.reserve(HK, cp, {"models": ["m"], "mcp_servers": None}, SECRET)
    settled = settled_checkpoint(cp, first)
    await service.credit(mg.CreditRequest(**scope(store, previous_max_budget="0",
        previous_checkpoint=cp, expected_checkpoint=settled, settlement=first,
        target_max_budget="1", amount_units=first.amount_units)))
    # Only a credit may move settled totals or receipts.
    for forged in ({**settled, "total_settled_units": 9_000_000_000},
                   {**settled, "receipt_ids": []}):
        with pytest.raises(mg.ManagingConflict, match="only a credit"):
            await service.checkpoint(mg.CheckpointRequest(**scope(store, previous_max_budget="1",
                expected_checkpoint=settled, checkpoint=forged)))
    observed, intent, second = top_up_intent(settled, 500_000_000, 20)
    for step, target in ((settled, observed), (observed, intent)):
        await service.checkpoint(mg.CheckpointRequest(**scope(store, previous_max_budget="1",
            expected_checkpoint=step, checkpoint=target)))
    # An operator (or a lost write) moved max_budget away from the receipts.
    store.row.max_budget = "5"
    with pytest.raises(mg.HTTPException) as refused:
        await service.credit(mg.CreditRequest(**scope(store, previous_max_budget="5",
            previous_checkpoint=intent, expected_checkpoint=settled_checkpoint(intent, second),
            settlement=second, target_max_budget="5.5", amount_units=second.amount_units)))
    assert refused.value.status_code == 409 and "settled Gamma total" in str(refused.value.detail)
    assert store.credit_writes == 1 and store.row.max_budget == "5"
    store.row.max_budget = "1"
    # An operator block survives a top-up and stops delivery; nothing re-enables it.
    store.row.blocked = True
    await service.credit(mg.CreditRequest(**scope(store, previous_max_budget="1",
        previous_checkpoint=intent, expected_checkpoint=settled_checkpoint(intent, second),
        settlement=second, target_max_budget="1.5", amount_units=second.amount_units)))
    assert store.row.blocked is True and store.row.max_budget == "1.5"
    with pytest.raises(mg.HTTPException) as blocked:
        await service.issue(HK, "claim", "a" * 64)
    assert blocked.value.status_code == 409 and store.row.blocked is True


@pytest.mark.asyncio
async def test_signed_claim_real_worker_then_private_native_key(worker_identity, monkeypatch):
    from worker.service import WorkerService
    from worker.reconciler import Reconciler
    from worker.protocol import internal_router
    from bittensor_core import Keypair
    import bittensor as bt
    keypair = Keypair.create_from_mnemonic(Keypair.generate_mnemonic(12), crypto_type=bt.CRYPTO_SR25519)
    monkeypatch.setattr(sys.modules[__name__], "HK", keypair.ss58_address)
    chain = SyntheticChain()
    chain.HK = HK
    store = SyntheticStore()
    chain.mint(1_000_000_000)
    native, native_http = management(store, worker_identity)
    from kubetee_gamma_private_mtls import InProcessIssueClient
    delivery = InProcessIssueClient(native)
    reconciler = Reconciler(
        chain, Management(native_http, "https://internal.invalid", "narrow worker credential"),
        None, signer=object())
    worker_service = WorkerService(chain, lambda hotkey: chain.finalized_snapshot(hotkey),
                                    reconciler, certificate_fingerprint=worker_identity[1])
    # This test isolates cross-service orchestration; the worker suite independently
    # exercises right/wrong X.509 authentication on the real internal router.
    async def trusted_sidecar(proof):
        assert proof == "synthetic-auth-test"
    worker_service.authenticate = trusted_sidecar
    worker_app = FastAPI()
    worker_app.include_router(internal_router(worker_service))
    worker_http = AsyncClient(transport=ASGITransport(app=worker_app), base_url="https://worker.invalid")
    bridge = PrivateWorkerResponse(worker_http, delivery,
        worker_headers={"x-kubetee-worker-proof": "synthetic-auth-test"})
    public = FastAPI()
    KubeTEEGammaClaimHandler(bridge, authority=MemoryAuthority()).register(public)
    async with native_http, worker_http, AsyncClient(transport=ASGITransport(app=public), base_url="https://public.invalid") as client:
        challenge = (await client.post("/v1/gamma/challenge", json={"hotkey_ss58": keypair.ss58_address,
            "netuid": 90, "action": "claim"})).json()
        response = await client.post("/v1/gamma/key/claim", json={"challenge_id": challenge["challenge_id"],
            "signature": keypair.sign(challenge["message"]).hex()})
        assert response.status_code == 200, response.text
        assert response.json() == {"status": "provisioned", "api_key": store.secret, "remaining_credit": "1"}
        # New signed challenge + repeat claim returns the same stored vk: no
        # fresh credit, second key, or second GammaSpent submission.
        # Production throttles one fresh challenge per IP/H every six seconds.
        # Advance only the synthetic clock; real signed proof + abuse controls remain.
        clock = time.monotonic()
        monkeypatch.setattr(time, "monotonic", lambda: clock + 6.01)
        repeat = (await client.post("/v1/gamma/challenge", json={"hotkey_ss58": keypair.ss58_address,
            "netuid": 90, "action": "claim"})).json()
        assert set(("challenge_id", "message")) <= repeat.keys(), {"challenge": repeat, "first_claim": response.text}
        response = await client.post("/v1/gamma/key/claim", json={"challenge_id": repeat["challenge_id"],
            "signature": keypair.sign(repeat["message"]).hex()})
        assert response.status_code == 200, response.text
        assert response.json()["api_key"] == store.secret
    assert store.credit_writes == 1 and len(chain.submitted) == 1
    assert store.rotations == 0 and store.row.blocked is False
    assert json.loads(store.row.metadata)["gamma_hotkey"] == keypair.ss58_address


@pytest.mark.asyncio
async def test_no_native_secret_response_without_definitive_worker_funding():
    class Response:
        status_code = 503
        def json(self):
            return {"status": "retryable_error"}
        text = ""

    class WorkerTransport:
        def __init__(self): self.calls = 0
        async def post(self, *args, **kwargs):
            self.calls += 1
            return Response()

    class NativeTransport:
        def __init__(self): self.calls = 0
        async def post(self, *args, **kwargs):
            self.calls += 1
            return {"unexpected": "never reached"}

    class UnsignedWorker:
        native_credit_callback_configured = True
        trusted_proxy_ips: tuple[str, ...] = ()
        ready = True
        async def claim(self, body):
            raise AssertionError("signature must be verified before worker invocation")
        rotate = claim
        reconcile = claim
        native_credit_callback_configured = True
        async def status(self, hotkey): raise AssertionError("no unsigned private call")

    transport, native_worker = WorkerTransport(), NativeTransport()
    with pytest.raises(RuntimeError, match="in-process"):
        PrivateWorkerResponse(transport, native_worker)
    assert transport.calls == 0 and native_worker.calls == 0
    public = FastAPI()
    KubeTEEGammaClaimHandler(UnsignedWorker(), authority=MemoryAuthority()).register(public)
    async with AsyncClient(transport=ASGITransport(app=public), base_url="https://public.invalid") as client:
        challenge = (await client.post("/v1/gamma/challenge", json={"hotkey_ss58": HK, "netuid": 90, "action": "regenerate"})).json()
        response = await client.post("/v1/gamma/key/regenerate", json={"challenge_id": challenge["challenge_id"],
            "signature": "0" * 128})
        assert response.status_code == 403


def test_internal_routes_do_not_exist_without_explicit_enablement(monkeypatch):
    monkeypatch.delenv("KUBETEE_GAMMA_ENABLED", raising=False)
    application = FastAPI()
    assert mg.installed_router(application) is None
    assert not any(route.path.startswith("/internal/v1/gamma") for route in application.routes)
    assert callable(mg.kubetee_gamma_management_proxy)
