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

# Lease fencing mutex applies to native row transitions, including zero reservations.

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

ROOT = Path(__file__).resolve().parents[4]
import os
SUBNET = Path(os.environ["KUBETEE_GAMMA_WORKER_ROOT"]).resolve()
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
        "last_spent_reference": s.reference, "total_settled_units": s.amount_units,
        "receipt_ids": [*cp["receipt_ids"], s.model_dump(exclude={"observation_hash"})]})
    return next_cp


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
            key_alias=COLD, metadata=json.dumps({"gamma_hotkey": HK, "gamma_netuid": 90,
                "gamma_network": "finney", "gamma": checkpoint}),
            updated_at=datetime.now(timezone.utc), max_budget="0", spend="0",
            blocked=True, models=permissions["models"], team_id=None,
            object_permission={"mcp_servers": permissions["mcp_servers"]})
        self.secret = secret
        return self.row

    async def compare_checkpoint(self, hotkey, expected, checkpoint, expected_max_budget,
                                 expected_spend, *, target_max_budget=None):
        await asyncio.sleep(0)
        md = json.loads(self.row.metadata)
        if (hotkey != HK or md["gamma"] != expected
                or Decimal(self.row.max_budget) != Decimal(expected_max_budget)
                or Decimal(self.row.spend) != Decimal(expected_spend)):
            raise mg.ManagingConflict("stale native row")
        md["gamma"] = checkpoint
        self.row.metadata = json.dumps(md)
        self.row.updated_at = datetime.now(timezone.utc)
        if target_max_budget is not None:
            self.row.max_budget = target_max_budget
            self.credit_writes += 1
        return self.row

    async def compare_and_checkpoint(self, hotkey, expected, checkpoint, previous_max_budget,
                                     target_max_budget, expected_spend):
        return await self.compare_checkpoint(hotkey, expected, checkpoint, previous_max_budget,
                                             expected_spend, target_max_budget=target_max_budget)

    async def stored_key(self, row):
        return self.secret

    async def evict(self, token):
        assert token == self.row.token

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
                assert where == {"token": store.row.token} and data == {"blocked": False}
                store.row.blocked = False
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


def management(store, identity):
    certificate, _ = identity
    class VerifiedSocket:
        def get_extra_info(self, name):
            assert name == "ssl_object"
            return self
        def getpeercert(self, binary_form):
            assert binary_form is True
            return b64decode(certificate.replace("\n", ""), validate=True)
    asgi = ASGITransport(app=app(store, identity), client=("127.0.0.1", 1234))
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
    return http, Management(http, "https://internal.invalid", "narrow worker credential")


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
    http, worker = management(store, worker_identity)
    async with http:
        assert await worker.info(HK) is None
        cp, settlement = settlement_intent()
        row = await worker.reserve(HK, cp["pending"]["expected_checkpoint"])
        assert row["key_alias"] == COLD and Decimal(row["max_budget"]) == 0
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
    http, worker = management(store, worker_identity)
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
    first = await service.issue(HK, "claim", "a" * 64)
    assert first["status"] == "provisioned" and first["has_positive_chain_settlement"] is True
    assert first["remaining_credit"] == "1"
    assert validate_claimed_result(first, True)["api_key"] == SECRET
    assert (await service.issue(HK, "claim", "b" * 64))["api_key"] == SECRET
    assert store.credit_writes == 1 and store.rotations == 0
    assert (await service.issue(HK, "regenerate", "c" * 64))["api_key"] == ROTATED
    assert store.rotations == 1 and store.row.blocked is False
    assert Decimal(store.row.max_budget) == 1 and Decimal(store.row.spend) == 0


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
    native_http, native = management(store, worker_identity)
    reconciler = Reconciler(chain, native, None, signer=object())
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
    native_http.base_url = "https://native.invalid"
    bridge = PrivateWorkerResponse(worker_http, native_http,
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
    bridge = PrivateWorkerResponse(transport, native_worker, worker_headers={})
    code, result = await bridge.claim({"hotkey_ss58": HK, "action": "regenerate", "verified_challenge_digest": "a" * 64})
    assert code == 503 and result == {"status": "retryable_error"}
    assert transport.calls == 1 and native_worker.calls == 0
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
