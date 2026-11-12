"""Private SN90 Gamma / LiteLLM virtual-key boundary.

Only the separately attested worker may call this API. The public overlay never
calls these methods. Native max_budget / spend remain ordinary LiteLLM money;
Gamma's tiny technical checkpoint sits in the existing key metadata. No SQL,
receipt table, alternate budget, arbitrary metadata mutation, or master key
fallback is exposed. Production Prisma metadata is a serialized JSON column,
not a structured Json field; whole-metadata compare-and-swap is therefore used.
"""
from __future__ import annotations

import asyncio
import contextlib
import secrets
import hashlib
import hmac
import ipaddress
import json
import os
import re
from base64 import b64decode
from datetime import datetime, timezone
from decimal import Decimal, DecimalException
from types import MappingProxyType
from typing import Any, Literal

from cryptography import x509
from fastapi import APIRouter, Body, Depends, FastAPI, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator

from kubetee_gamma_scope import GENESIS, assert_hotkey, settlement_reference

NETWORK, NETUID, UNITS = "finney", 90, 10**9


class ManagingConflict(RuntimeError):
    """The live native row changed between worker preparation and CAS."""


class ChainScope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    network: Literal["finney"]
    genesis_hash: Literal[GENESIS]
    netuid: Literal[NETUID]
    hotkey_ss58: str = Field(min_length=48, max_length=48)


class ProvenanceSettlement(BaseModel):
    model_config = ConfigDict(extra="forbid")
    block_number: int = Field(ge=1)
    observation_hash: str = Field(pattern=r"^0x[0-9a-f]{64}$")
    hotkey_ss58: str = Field(min_length=48, max_length=48)
    amount_units: int = Field(gt=0)
    reference: str = Field(pattern=r"^0x[0-9a-f]{64}$")
    block_hash: str = Field(pattern=r"^0x[0-9a-f]{64}$")
    event_index: int = Field(ge=-1)
    netuid: Literal[NETUID]

    @model_validator(mode="after")
    def reference_binds_signed_observation(self):
        # Worker proves the digest over its exact-H challenge. The settlement
        # witness binds H/block/amount/netuid/genesis (runtime defines ref).
        # Never infer challenger H from a funder coldkey or loose observation.
        expected = settlement_reference(netuid=self.netuid, hotkey=self.hotkey_ss58,
                                        observation_hash=self.observation_hash, units=self.amount_units)
        if self.reference != expected:
            raise ValueError("settlement reference does not bind observed hotkey/block/amount")
        return self

    @classmethod
    def from_settlement(cls, settlement: dict[str, Any], observation_hash: str):
        return cls.model_validate({**settlement, "observation_hash": observation_hash})


class ReservationRequest(ChainScope):
    checkpoint: dict[str, Any]
    key_alias: str = Field(min_length=1, max_length=255)
    target_permissions: dict[str, Any] | None = None


class RowReference(ChainScope):
    token_id: str = Field(min_length=16, max_length=128)
    row_version: str | None = None  # native metadata/token CAS; timestamps are advisory
    previous_max_budget: str
    previous_spend: str


class CheckpointRequest(RowReference):
    expected_checkpoint: dict[str, Any] | None
    checkpoint: dict[str, Any]


class CreditRequest(RowReference):
    previous_checkpoint: dict[str, Any]
    settlement: ProvenanceSettlement
    expected_checkpoint: dict[str, Any]
    target_max_budget: str
    amount_units: int = Field(gt=0)


class IssueRequest(ChainScope):
    model_config = ConfigDict(extra="forbid")
    action: Literal["claim", "regenerate"] = "claim"
    verification_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


def decode_metadata(value: object) -> dict[str, Any]:
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, dict):
        raise ManagingConflict("native virtual-key metadata is not an object")
    return value


def metadata_json(value: dict[str, Any]) -> str:
    # Existing Prisma writes use ordinary json.dumps. Preserve its exact bytes so
    # serialized-metadata CAS cannot race two equivalent orderings unexpectedly.
    return json.dumps(value)


def exact_units(value: object) -> int:
    try:
        units = Decimal(str(value)) * UNITS
        if not units.is_finite() or units < 0 or units != units.to_integral_value():
            raise ManagingConflict("nonexact native money")
        return int(units)
    except (DecimalException, TypeError, ValueError) as error:
        raise ManagingConflict("native money is not exact Gamma base units") from error


def units_text(value: int) -> str:
    return format(Decimal(value) / UNITS, "f")


def require_reference(checkpoint: dict[str, Any], settlement: ProvenanceSettlement) -> None:
    pending = checkpoint.get("pending")
    if not isinstance(pending, dict):
        raise ManagingConflict("no durable settlement intent")
    expected = pending.get("reference")
    if not isinstance(expected, dict):
        raise ManagingConflict("invalid fenced settlement reference")
    for name in ("reference", "hotkey_ss58", "netuid", "amount_units"):
        if expected.get(name) != getattr(settlement, name):
            raise ManagingConflict(f"settlement does not fence {name}")
    if expected.get("block_hash") != settlement.observation_hash:
        raise ManagingConflict("settlement does not bind the observed planning block")
    if (pending.get("planning_hash") != settlement.observation_hash
            or pending.get("intake_height") != expected.get("block_number")):
        raise ManagingConflict("protected planning height/hash mismatch")
    if pending.get("attempts") != 1 or pending.get("expected_checkpoint") is None:
        raise ManagingConflict("non-single-attempt exact spending intent")


class NativeKeys:
    """Small selected native virtual-key operations, not another accounting DB."""

    def __init__(self, proxy: Any):
        self.proxy = proxy

    async def table(self):
        from litellm.proxy.management_endpoints.key_management_endpoints import (
            VerificationTokenRepository, _prisma_table,
        )
        return _prisma_table(VerificationTokenRepository(self.proxy.prisma_client))

    async def find_exact_hotkey(self, hotkey: str):
        table = await self.table()
        # Serialized Prisma metadata cannot use metadata.gamma_hotkey filters.
        # Bounded full pages, Gamma-marker prefilter; never return raw key columns
        # or unrelated arbitrary field mutation to this application.
        found, before = None, 0
        while before < 10_000:
            rows = await table.find_many(where={"metadata": {"contains": '"gamma_netuid": 90'}},
                                         skip=before, take=250, include={"object_permission": True})
            before += len(rows)
            for row in rows:
                metadata = decode_metadata(row.metadata)
                if metadata.get("gamma_hotkey") == hotkey:
                    if found is not None:
                        raise ManagingConflict("duplicate exact-hotkey identities")
                    found = row
            if len(rows) < 250:
                break
        if before >= 10_000:
            raise ManagingConflict("too many native Gamma rows to safely enumerate")
        return found

    async def gamma_identities(self) -> list[dict[str, Any]]:
        """Read the existing Gamma key index without returning customer secrets."""
        rows, before = [], 0
        while before < 10_000:
            table = await self.table()
            chunk = await table.find_many(where={"metadata": {"contains": '"gamma_netuid": 90'}},
                skip=before, take=250, include={"object_permission": True})
            for row in chunk:
                _project(row)
                cp = row.metadata.get("gamma")
                if isinstance(cp, dict) and cp.get("schema") == 1:
                    rows.append({"metadata": {"gamma": cp}})
            if len(chunk) < 250:
                return rows
            before += len(chunk)
        raise ManagingConflict("Gamma native index exceeds bounded lookup")


    async def reserve(self, hotkey: str, checkpoint: dict[str, Any], permissions: dict[str, Any], secret: str):
        from litellm.proxy._types import GenerateKeyRequest, LitellmUserRoles, UserAPIKeyAuth
        from litellm.proxy.management_endpoints.key_management_endpoints import generate_key_fn
        if await self.find_exact_hotkey(hotkey) is not None:
            raise ManagingConflict("identity already reserved")
        data = GenerateKeyRequest.model_validate({
            "key": secret, "key_alias": checkpoint["observation_coldkey"],
            "max_budget": 0.0, "spend": 0.0, "blocked": True, "budget_duration": None,
            "models": permissions["models"], "metadata": {"gamma": checkpoint,
            "gamma_hotkey": hotkey, "gamma_netuid": NETUID, "gamma_network": NETWORK},
            "key_type": "llm_api", **({"object_permission": {"mcp_servers": permissions["mcp_servers"]}}
                                      if permissions.get("mcp_servers") is not None else {}),
        })
        # The full native generate_key_fn is required, not its lower-level
        # helper: the route lifecycle persists and later rotates the virtual
        # key in LiteLLM's configured stored-virtual-keys secret manager.
        response = await generate_key_fn(data=data,
            user_api_key_dict=UserAPIKeyAuth(user_role=LitellmUserRoles.PROXY_ADMIN.value,
                                             user_id="kubetee-sn90-gamma-funder"),
            litellm_changed_by="kubetee-sn90-gamma-funder", team_table=None)
        row = await self.find_exact_hotkey(hotkey)
        if row is None or getattr(response, "token", None) != row.token or response.token != hashlib.sha256(response.key.encode()).hexdigest():
            raise ManagingConflict("native reservation readback failed")
        if row.blocked is not True or exact_units(row.max_budget) != 0:
            raise ManagingConflict("reserved virtual key is usable before proof of credit")
        return row

    async def compare_checkpoint(self, hotkey: str, expected: dict[str, Any] | None,
                                 checkpoint: dict[str, Any], expected_max_budget: str,
                                 expected_spend: str, *, target_max_budget: str | None = None):
        row = await self.find_exact_hotkey(hotkey)
        if row is None:
            raise ManagingConflict("native identity disappeared")
        metadata = decode_metadata(row.metadata)
        if (metadata.get("gamma") != expected or exact_units(row.spend) != exact_units(expected_spend)
                or exact_units(row.max_budget) != exact_units(expected_max_budget)):
            raise ManagingConflict("unchanged version required for conditional transition")
        updated_metadata = {**metadata, "gamma": checkpoint}
        payload: dict[str, object] = {"metadata": updated_metadata, "updated_at": datetime.now(timezone.utc)}
        if target_max_budget is not None:
            if exact_units(target_max_budget) != exact_units(expected_max_budget) + exact_units(pending_amount(checkpoint, expected)):
                raise ManagingConflict("target is not previous max_budget + proven Gamma units")
            payload["max_budget"] = float(Decimal(target_max_budget))
        table = await self.table()
        changed = await table.update_many(
            where={"token": row.token, "metadata": row.metadata, "spend": row.spend,
                   "max_budget": row.max_budget, "updated_at": row.updated_at},
            data=self.proxy.prisma_client.jsonify_object(payload),
        )
        if changed != 1:
            raise ManagingConflict("native compare-and-swap lost race")
        await self.evict(row.token)
        return await self.find_exact_hotkey(hotkey)

    async def compare_and_checkpoint(self, hotkey: str, expected: dict[str, Any],
                                     checkpoint: dict[str, Any], previous_max_budget: str,
                                     target_max_budget: str, expected_spend: str):
        # This is ONE conditional Prisma row update; no two-request read/add loop.
        return await self.compare_checkpoint(
            hotkey, expected, checkpoint, previous_max_budget, expected_spend,
            target_max_budget=target_max_budget,

        )

    async def evict(self, token: str):
        from litellm.proxy.auth.auth_checks import delete_cache_key_object
        await delete_cache_key_object(token, self.proxy.user_api_key_cache, self.proxy.proxy_logging_obj)

    async def rotate(self, hotkey: str) -> tuple[Any, str]:
        from litellm.proxy._types import LitellmUserRoles, RegenerateKeyRequest, UserAPIKeyAuth
        from litellm.proxy.management_endpoints.key_management_endpoints import regenerate_key_fn
        row = await self.find_exact_hotkey(hotkey)
        if row is None:
            raise ManagingConflict("no funded identity to rotate")
        response = await regenerate_key_fn(key=row.token,
            data=RegenerateKeyRequest(key=row.token, key_alias=row.key_alias),
            user_api_key_dict=UserAPIKeyAuth(user_role=LitellmUserRoles.PROXY_ADMIN.value,
                                             user_id="kubetee-sn90-gamma-funder"),
            litellm_changed_by="kubetee-sn90-gamma-funder")
        if response is None or not response.key:
            raise RuntimeError("native key rotation had no definitive result")
        return await self.find_exact_hotkey(hotkey), response.key

    async def stored_key(self, row: Any) -> str | None:
        from litellm.proxy.hooks.key_management_event_hooks import KeyManagementEventHooks
        manager = KeyManagementEventHooks._stored_virtual_key_secret_manager()
        if manager is None or not row.key_alias:
            return None
        return await manager.async_read_secret(
            secret_name=KeyManagementEventHooks._get_secret_name(row.key_alias),
            optional_params=await KeyManagementEventHooks._get_secret_manager_optional_params(row.team_id),
        )

    def available_key(self, hotkey: str):
        raise RuntimeError("worker-only raw-vk delivery is not available through native row read")


def pending_amount(_checkpoint: dict[str, Any], expected: dict[str, Any]) -> int:
    pending = expected.get("pending") if isinstance(expected, dict) else None
    if not isinstance(pending, dict) or not isinstance(pending.get("reference"), dict):
        raise ManagingConflict("conditional credit requires exact pending intent")
    return pending["reference"]["amount_units"]


def _project(row: Any) -> dict[str, Any]:
    return {
        "token_id": row.token, "version": row.updated_at.isoformat(), "max_budget": str(row.max_budget),
        "spend": str(row.spend), "key_alias": row.key_alias, "models": list(row.models or []),
        "team_id": row.team_id, "metadata": decode_metadata(row.metadata),
        "object_permission": decode_metadata(row.object_permission) if isinstance(row.object_permission, str) else (
            row.object_permission.model_dump() if hasattr(row.object_permission, "model_dump") else row.object_permission),
        "blocked": row.blocked,
    }


class GammaManagement:
    """Setter-injected application adapter, with no native modules imported at startup."""
    def __init__(self, *, certificate_fingerprint: str, proxy_ip: str = "127.0.0.1",
                 models: list[str] | None = None, mcp_servers: list[str] | None = None,
                 proxy: Any = None):
        if not re.fullmatch(r"[0-9a-f]{64}", certificate_fingerprint.lower()):
            raise ValueError("explicit Gamma-worker certificate fingerprint required")
        ipaddress.ip_address(proxy_ip)
        if not models or len(set(models)) != len(models):
            raise ValueError("explicit nonempty unique native models required")
        if mcp_servers is not None and not isinstance(mcp_servers, list):
            raise ValueError("explicit MCP permission list or null required")
        self.fingerprint = certificate_fingerprint.lower()
        self.proxy_ip = proxy_ip
        self.models = models or []
        self.mcp_servers = mcp_servers
        self.proxy = proxy
        self.locks: dict[str, asyncio.Lock] = {}
        self.state_lock = asyncio.Lock()
        # Set only by the measured bridge after Redis succeeds. Synthetic
        # test adapters remain local-only; production cannot omit this mutex.
        self.issuance_lease = None

    async def protected_issue(self, hotkey: str, action: str, digest: str) -> dict[str, Any]:
        """Private proxy boundary retained for signed claim request compatibility."""
        return await self.issue(hotkey, action, digest)

    def assert_hotkey(self, hotkey: str) -> None:
        try:
            assert_hotkey(hotkey)
        except (ValueError, TypeError) as error:
            raise HTTPException(422, {"status": "ineligible", "reason": "invalid_hotkey"}) from error
        if not re.fullmatch(r"[0-9a-f]{64}", self.fingerprint):
            raise ValueError("explicit Gamma-worker certificate fingerprint required")
        ipaddress.ip_address(self.proxy_ip)
        if not self.models or len(set(self.models)) != len(self.models):
            raise ValueError("explicit nonempty unique native models required")

    async def authenticate(self, request: Request) -> None:
        # Only the dedicated CERT_REQUIRED listener's PrivateTransportCycle
        # may place this header in scope. Its value comes directly from the
        # TLS peer after the server strips every inbound proof header. The
        # separate public Granian application never has this bridge.
        self.validate_worker_cert(request.headers.get("x-kubetee-worker-cert-der"))

    def validate_worker_auth(self, ip: str | None, request: Any) -> None:
        if self.proxy_ip and ip != self.proxy_ip:
            raise HTTPException(403, {"status": "ineligible", "reason": "private callback listener required"})

    def validate_worker_cert(self, raw: str | None) -> None:
        try:
            der = b64decode(raw, validate=True)
            from cryptography import x509
            certificate = x509.load_der_x509_certificate(der)
            certificate.not_valid_after_utc  # trust path ends at mTLS sidecar
        except (ValueError, TypeError) as error:
            raise HTTPException(403, {"status": "ineligible", "reason": "invalid worker certificate"}) from error
        if not hmac.compare_digest(hashlib.sha256(der).hexdigest(), self.fingerprint):
            raise HTTPException(403, {"status": "ineligible", "reason": "wrong worker certificate"})

    async def keys(self) -> NativeKeys:
        if self.proxy is not None:
            return self.proxy
        from litellm.proxy import proxy_server
        if proxy_server.prisma_client is None:
            raise HTTPException(503, {"error": "native virtual-key backend unavailable"})
        return NativeKeys(proxy_server)

    async def key(self, hotkey_ss58: str = Query(min_length=48, max_length=48),
                  network: Literal["finney"] = "finney", genesis_hash: Literal[GENESIS] = GENESIS,
                  netuid: Literal["90"] = "90") -> dict[str, Any]:
        self.assert_hotkey(hotkey_ss58)
        row = await (await self.keys()).find_exact_hotkey(hotkey_ss58)
        return {"exists": row is not None, "row": None if row is None else _project(row)}

    async def reserve(self, body: ReservationRequest):
        if body.checkpoint.get("observation_coldkey") != body.key_alias:
            raise HTTPException(403, {"error": "coldkey alias must be observed from finalized chain"})
        if any(body.checkpoint.get(field) for field in ("total_settled_units", "last_spent_reference")):
            raise HTTPException(403, {"error": "reservation cannot fabricate settled credit"})
        if body.target_permissions is not None and body.target_permissions != {"models": self.models, "mcp_servers": self.mcp_servers}:
            raise HTTPException(403, {"error": "permission widening is not permitted"})
        import secrets
        secret = "sk-" + secrets.token_urlsafe(32)
        row = await (await self.keys()).reserve(body.hotkey_ss58, body.checkpoint,
                    {"models": self.models, "mcp_servers": self.mcp_servers}, secret)
        return {"exists": True, "row": _project(row)}

    async def checkpoint(self, body: CheckpointRequest):
        pending = body.checkpoint.get("pending")
        if body.expected_checkpoint.get("pending") is not None:
            raise ManagingConflict("already pending intent requires finalized recovery, not a replacement")
        if isinstance(pending, dict):
            if body.expected_checkpoint != pending.get("expected_checkpoint"):
                raise ManagingConflict("pending settlement is in progress; compare and recover its intent")
            require_reference(body.checkpoint, ProvenanceSettlement.from_settlement(
                pending["reference"], pending["planning_hash"]))
        row = await (await self.keys()).compare_checkpoint(body.hotkey_ss58,
            body.expected_checkpoint, body.checkpoint, body.previous_max_budget, body.previous_spend)
        if row is None:
            raise ManagingConflict("conditional write readback failed")
        expected_units = exact_units(body.previous_max_budget)
        if exact_units(row.max_budget) != expected_units or exact_units(row.spend) != exact_units(body.previous_spend):
            raise ManagingConflict("checkpoint endpoint cannot change native money")
        return {"row": _project(row)}

    async def credit(self, body: CreditRequest):
        if body.amount_units != body.settlement.amount_units or body.settlement.hotkey_ss58 != body.hotkey_ss58:
            raise HTTPException(403, {"error": "inconsistent chain settlement identity"})
        require_reference(body.previous_checkpoint, body.settlement)
        cp = body.expected_checkpoint
        if cp.get("pending") is not None or any(r.get("reference") == body.settlement.reference for r in body.previous_checkpoint.get("receipt_ids", [])):
            return {"error": "settlement intent already consumed", "conflict": True}
        expected_record = body.settlement.model_dump(exclude={"observation_hash"})
        if cp.get("receipt_ids") != [*body.previous_checkpoint.get("receipt_ids", []), expected_record]:
            raise HTTPException(403, {"error": "receipt is not appended exactly once"})
        if cp.get("last_spent_reference") != body.settlement.reference or cp.get("last_spent_height") != body.settlement.block_number:
            raise HTTPException(403, {"error": "checkpoint does not connect the successful finalized spend"})
        if body.previous_checkpoint.get("total_settled_units", 0) + body.settlement.amount_units != cp.get("total_settled_units"):
            raise HTTPException(403, {"error": "chain-settled totals cannot be inferred backwards"})
        if exact_units(body.previous_max_budget) + body.settlement.amount_units != exact_units(body.target_max_budget):
            raise HTTPException(409, {"error": "target is not prior native max_budget plus confirmed Gamma"})
        row = await (await self.keys()).compare_and_checkpoint(body.hotkey_ss58,
            body.previous_checkpoint, cp, body.previous_max_budget, body.target_max_budget, body.previous_spend)
        if row is None:
            raise ManagingConflict("settlement write did not persist")
        if decode_metadata(row.metadata).get("gamma") != cp or exact_units(row.max_budget) != exact_units(body.target_max_budget):
            raise RuntimeError("native credit readback failed")
        return {"row": _project(row)}

    async def credit_replay(self, body: CreditRequest):
        live = await self.key(body.hotkey_ss58)
        if live and live["metadata"].get("gamma", {}).get("last_spent_reference") == body.settlement.reference:
            return {"error": "settlement intent already consumed"}
        return await self.credit(body)

    async def issue(self, hotkey: str, action: str, verification_digest: str) -> dict[str, Any]:
        """Serialize issue/rotate across workers of this process and replicas.

        The public handler holds the per-key sequencer. This bounded Redis
        lease additionally excludes a second gateway instance; any lease
        timeout or loss prevents a potentially revoked credential's delivery.
        """
        if action not in ("claim", "regenerate") or not re.fullmatch(r"[0-9a-f]{64}", verification_digest):
            raise HTTPException(422, {"error": "key claim requires exact challenge context"})
        self.assert_hotkey(hotkey)
        async with self.state_lock:
            lock = self.locks.setdefault(hotkey, asyncio.Lock())
        async with lock:
            if self.issuance_lease is None:
                return await self._issue_serialized(hotkey, action)
            lock_key = "kubetee:gamma:key-issue-lease:v1:" + hotkey
            import secrets
            # Signed challenge contents never choose the lease owner; each
            # process gets an independent token even on the same hotkey.
            token = secrets.token_urlsafe(32)
            deadline = asyncio.get_running_loop().time() + 45
            while not await self.issuance_lease.set(lock_key, token, nx=True, ex=60):
                if asyncio.get_running_loop().time() > deadline:
                    raise HTTPException(503, {"status": "pending", "reason": "key_issuance_in_progress"})
                await asyncio.sleep(0.2)
            owner_script = self.issuance_lease.register_script(
                "if redis.call('GET',KEYS[1]) == ARGV[1] then "
                "return redis.call('EXPIRE',KEYS[1],60) else return 0 end")
            release_script = self.issuance_lease.register_script(
                "if redis.call('GET',KEYS[1]) == ARGV[1] then "
                "return redis.call('DEL',KEYS[1]) else return 0 end")
            renew_failed = asyncio.Event()
            async def assert_lease_owner():
                owned = await asyncio.wait_for(owner_script(
                    keys=[lock_key], args=[token]), 5)
                if renew_failed.is_set() or owned != 1:
                    raise RuntimeError("distributed key-issuance fencing lease lost")
            async def renew():
                try:
                    while True:
                        await asyncio.sleep(1)
                        await assert_lease_owner()
                except asyncio.CancelledError:
                    return
                except BaseException as error:
                    renew_failed.set()
                    if not isinstance(error, Exception):
                        raise
            renewal = asyncio.create_task(renew())
            try:
                result_task = asyncio.create_task(self._issue_serialized(hotkey, action))
                while not result_task.done():
                    try:
                        await asyncio.wait_for(asyncio.shield(result_task), 1)
                    except asyncio.TimeoutError:
                        await assert_lease_owner()
                if renewal.done():
                    failure = renewal.exception()
                    raise HTTPException(503, {"status": "pending", "reason": "key_issuance_in_progress"}) from failure
                result = await result_task
                # Validate immediately before the raw credential is serialized.
                await assert_lease_owner()
                return result
            except RuntimeError as error:
                renewal.cancel()
                raise HTTPException(503, {"status": "pending", "reason": "key_issuance_in_progress"}) from error
            finally:
                renewal.cancel()
                with contextlib.suppress(asyncio.CancelledError, asyncio.TimeoutError):
                    await asyncio.wait_for(renewal, 5)
                # Renewal's returned cancellations are intentional here; a
                # lost ownership check after shutdown maps to bounded pending.
                try:
                    await assert_lease_owner()
                except RuntimeError as error:
                    raise HTTPException(503, {"status": "pending", "reason": "key_issuance_in_progress"}) from error
                with contextlib.suppress(BaseException):
                    await asyncio.wait_for(release_script(keys=[lock_key], args=[token]), 5)

    async def _issue_serialized(self, hotkey: str, action: str) -> dict[str, Any]:
        native = await self.keys()
        selected_token = None
        row = await native.find_exact_hotkey(hotkey)
        if row is None:
            raise HTTPException(409, {"error": "no native retention identity"})
        check = decode_metadata(row.metadata).get("gamma") or {}
        reference = check.get("last_spent_reference")
        if exact_units(row.max_budget) <= 0:
            raise HTTPException(409, {"error": "no positive finalized chain settlement"})
        if not isinstance(reference, str) or not reference:
            raise HTTPException(409, {"error": "no signed-chain reconciliation reference"})
        # Inference auth must see the unblocked row before any credential leaves
        # this process. Enable once through the ordinary unblocked native routine,
        # which also evicts its cached key state; never store a raw vk in metadata.
        if row.blocked:
            table = await native.table()
            updated = await table.update(where={"token": row.token}, data={"blocked": False})
            if updated is None or updated.blocked:
                raise ManagingConflict("native activation readback failed")
            await native.evict(row.token)
        if action == "regenerate":
            row, raw = await native.rotate(hotkey)
            if row is None or row.blocked:
                raise ManagingConflict("regenerated native key is not a funded active key")
        else:
            selected_token = row.token
            raw = await native.stored_key(row)
        if not isinstance(raw, str) or not raw.startswith("sk-"):
            return {"status": "pending", "error": "configured native virtual-key recovery unavailable"}
        if not hmac.compare_digest(hashlib.sha256(raw.encode()).hexdigest(), row.token):
            raise RuntimeError("native stored virtual-key hash mismatch; refusing delivery")
        row = await native.find_exact_hotkey(hotkey)
        if row is None:
            raise ManagingConflict("native identity disappeared during credential issue")
        if selected_token is not None and row.token != selected_token:
            # Never pair a credential read from one row with a newer row.
            raise ManagingConflict("credential changed during delivery; retry the claim")
        cp = decode_metadata(row.metadata).get("gamma", {})
        reference = cp.get("last_spent_reference")
        if cp.get("hotkey_ss58", hotkey) != hotkey or not isinstance(reference, str):
            raise ManagingConflict("settled checkpoint has wrong exact-H identity")
        return {"status": "provisioned", "has_positive_chain_settlement": True,
                "max_budget": str(row.max_budget), "spend": str(row.spend),
                "remaining_credit": units_text(exact_units(row.max_budget) - exact_units(row.spend)),
                "reconciliation_reference": reference,
                "models": list(row.models or []), "receipts": cp.get("receipt_ids", []),
                "api_key": raw}


def _environment_management() -> GammaManagement | None:
    if os.environ.get("KUBETEE_GAMMA_ENABLED", "").lower() not in ("true", "1"):
        return None
    return GammaManagement(
        certificate_fingerprint=os.environ.get("KUBETEE_GAMMA_WORKER_CLIENT_CERT_SHA256", ""),
        proxy_ip=os.environ.get("KUBETEE_GAMMA_SIDECAR_IP", "127.0.0.1"),
        models=[m for m in os.environ.get("KUBETEE_GAMMA_MODELS", "").split(",") if m],
        mcp_servers=[m for m in os.environ.get("KUBETEE_GAMMA_MCP_SERVERS", "").split(",") if m] or None,
    )


def installed_router(app: FastAPI, service: GammaManagement | None = None) -> APIRouter | None:
    """Private worker callback. Public Gamma dependency installs both callbacks."""
    if service is None:
        if os.environ.get("KUBETEE_GAMMA_ENABLED", "").lower() not in ("true", "1"):
            return None
    if service is None:
        # Environment-only activation must never put the budget/rotation API
        # on the public port-4000 app. Only the private CERT_REQUIRED app
        # explicitly supplies its measured service object.
        raise RuntimeError("Gamma management requires the dedicated private mTLS application")
    if not getattr(app.state, "kubetee_gamma_private_callback", False):
        raise RuntimeError("native Gamma mutation routes require dedicated private app")
    session = service
    from fastapi.responses import JSONResponse

    async def managing_conflict(_request: Request, error: ManagingConflict):
        return JSONResponse({"detail": {"error": str(error)}}, status_code=409)

    if ManagingConflict not in app.exception_handlers:
        app.add_exception_handler(ManagingConflict, managing_conflict)
    router = APIRouter()
    guarded = [Depends(session.authenticate)]
    async def readiness():
        return JSONResponse({"ready": True})
    router.add_api_route("/internal/v1/ready", readiness, methods=["GET"], dependencies=guarded)
    # schemas and checks as production; the fake chain edges live outside.
    # Scope-sensitive request, query/body and secret-free readiness only; never
    # expose private router mutation endpoints from the public 4000 application.
    router.add_api_route("/internal/v1/gamma/key", session.key, methods=["GET"], dependencies=guarded)
    async def gamma_index():
        native = await session.keys()
        if not hasattr(native, "gamma_identities"):
            raise HTTPException(503, {"detail": "single hotkey-only native test store"})
        return {"keys": await native.gamma_identities()}
    router.add_api_route("/internal/v1/gamma/keys", gamma_index, methods=["GET"], dependencies=guarded)
    router.add_api_route("/internal/v1/gamma/key/reservation", session.reserve, methods=["POST"], dependencies=guarded)
    router.add_api_route("/internal/v1/gamma/checkpoint", session.checkpoint, methods=["POST"], dependencies=guarded)
    router.add_api_route("/internal/v1/gamma/credit", session.credit, methods=["POST"], dependencies=guarded)
    async def issue(body: IssueRequest = Body(...)):
        return await session.issue(body.hotkey_ss58, body.action, body.verification_digest)
    router.add_api_route("/internal/v1/gamma/key/issue", issue, methods=["POST"], dependencies=guarded)
    app.include_router(router)
    return router


def kubetee_gamma_management_proxy():
    """Fail closed once explicitly enabled; never expose routes for partial config."""
    from litellm.integrations.custom_logger import CustomLogger

    class ManagementLogger(CustomLogger):
        def __init__(self):
            super().__init__()
            if _environment_management() is None:
                raise RuntimeError("Gamma requires explicit models and worker mTLS fingerprint")
            import kubetee_gamma_private_mtls as private
            private.create_private_application(_environment_management())
    return ManagementLogger()
