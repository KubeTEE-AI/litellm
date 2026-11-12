"""Private SN90 Gamma / LiteLLM virtual-key boundary.

Only the separately attested worker may call this API. The public overlay never
calls these methods. Native max_budget / spend remain ordinary LiteLLM money;
Gamma's tiny technical checkpoint sits in the existing key metadata. No SQL,
Prisma write, receipt table, alternate budget, arbitrary metadata mutation, or
master key fallback is exposed. This adapter calls only LiteLLM's native
generate/update/regenerate management handlers.

Accounting rule: ``max_budget`` is the only money this adapter changes and it
always equals ``metadata.gamma.total_settled_units``. A credit is ONE native
``/key/update`` carrying the receipt checkpoint and the new absolute
``max_budget`` together (LiteLLM persists one key update as one row write), so
no reader can observe a receipt without its allowance or the reverse. Native
``spend`` is LiteLLM's own usage meter: reported, never a precondition and
never an input to ``max_budget``.
"""
from __future__ import annotations

import asyncio
import copy
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
from types import SimpleNamespace
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
    # Accepted for wire compatibility and ignored: usage moves while a key is
    # in service, and Gamma credit never depends on it.
    previous_spend: str | None = None


class CheckpointRequest(RowReference):
    expected_checkpoint: dict[str, Any] | None
    checkpoint: dict[str, Any]


class CreditRequest(RowReference):
    previous_checkpoint: dict[str, Any]
    settlement: ProvenanceSettlement
    expected_checkpoint: dict[str, Any]
    target_max_budget: str
    amount_units: int = Field(gt=0)


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


def settled_total(checkpoint: object) -> int:
    """Total chain-settled Gamma base units recorded by a checkpoint."""
    total = checkpoint.get("total_settled_units", 0) if isinstance(checkpoint, dict) else None
    if isinstance(total, bool) or not isinstance(total, int) or total < 0:
        raise ManagingConflict("checkpoint has no exact settled Gamma total")
    return total


def native_budget(value: str) -> float:
    """LiteLLM stores max_budget as a float; refuse totals it cannot hold exactly."""
    number = float(Decimal(value))
    if exact_units(number) != exact_units(value):
        raise ManagingConflict("settled total is not exactly representable as native max_budget")
    return number


def usage_text(value: object) -> str:
    """Native spend for display. It is a float usage meter, not Gamma units."""
    try:
        spend = Decimal(str(value))
    except (DecimalException, TypeError, ValueError) as error:
        raise ManagingConflict("native spend is not a number") from error
    if not spend.is_finite() or spend < 0:
        raise ManagingConflict("native spend is not a finite nonnegative number")
    return format(spend, "f")


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

    async def admin(self):
        from litellm.proxy.auth.user_api_key_auth import user_api_key_auth
        import os
        from fastapi import Request
        raw = os.environ.get("KUBETEE_GAMMA_TEAM_MANAGEMENT_KEY", "")
        if not raw.startswith("sk-"):
            raise RuntimeError("Gamma team management key required")
        # Authentication is native LiteLLM, never a fabricated PROXY_ADMIN.
        # The service user is an admin member of only the configured Gamma team.
        auth = await user_api_key_auth(Request({
            "type": "http", "method": "POST", "path": "/key/info",
            "headers": [(b"authorization", f"Bearer {raw}".encode())],
            "query_string": b"", "scheme": "http", "server": ("127.0.0.1", 4001),
            "client": ("127.0.0.1", 4001)}))
        if auth.team_id != os.environ.get("KUBETEE_GAMMA_TEAM_ID"):
            raise ManagingConflict("management key is not scoped to the Gamma service team")
        if not auth.team_id or auth.user_id != os.environ.get("KUBETEE_GAMMA_USER_ID"):
            raise ManagingConflict("management key requires the dedicated Gamma service user and team")
        return auth

    async def _list_team_rows(self):
        """Enumerate only the service team using native management pagination.

        ``list_keys`` performs user/team membership and route authorization. Don't
        bypass it with a Prisma unread/read model query or a JSON-path predicate.
        No virtual-key secret is part of this handler's response.
        """
        from litellm.proxy.management_endpoints.key_management_endpoints import list_keys

        auth = await self.admin()
        team_id = os.environ.get("KUBETEE_GAMMA_TEAM_ID")
        if not team_id:
            raise ManagingConflict("Gamma service team is not configured")
        page = 1
        while True:
            result = await list_keys(
                request=Request({"type": "http", "method": "GET", "path": "/key/list",
                                 "headers": [], "query_string": b""}),
                user_api_key_dict=auth, page=page, size=100,
                team_id=team_id, user_id=auth.user_id,
                include_team_keys=True, return_full_object=True,
                sort_by="token", sort_order="asc",
            )
            rows = result.keys
            if any(not hasattr(row, "token") or row.team_id != team_id for row in rows):
                raise ManagingConflict("native key-list returned a foreign or secretless row")
            for row in rows:
                yield row
            if page >= result.total_pages:
                return
            page += 1
            if page > 100:
                raise ManagingConflict("Gamma native index exceeds bounded lookup")

    @staticmethod
    def _assert_gamma_row(row: Any):
        metadata = decode_metadata(row.metadata)
        if (metadata.get("gamma_netuid") != NETUID
                or metadata.get("gamma_network") != NETWORK
                or not isinstance(metadata.get("gamma_hotkey"), str)):
            raise ManagingConflict("service team contains a non-Gamma virtual-key identity")
        return metadata

    async def row_by_token(self, token: str):
        from litellm.proxy.management_endpoints.key_management_endpoints import info_key_fn
        result = await info_key_fn(key=token, user_api_key_dict=await self.admin())
        return SimpleNamespace(**{**result["info"], "token": token})

    async def update(self, row, *, metadata: dict[str, Any] | None = None,
                     max_budget: str | None = None, blocked: bool | None = None):
        from fastapi import Request
        from litellm.proxy._types import UpdateKeyRequest
        from litellm.proxy.management_endpoints.key_management_endpoints import update_key_fn
        result = await update_key_fn(
            request=Request({"type": "http", "method": "POST", "path": "/key/update",
                             "headers": [], "query_string": b""}),
            data=UpdateKeyRequest(key=row.token,
                **({"metadata": metadata} if metadata is not None else {}),
                **({"max_budget": native_budget(max_budget)} if max_budget is not None else {}),
                **({"blocked": blocked} if blocked is not None else {})),
            user_api_key_dict=await self.admin(), litellm_changed_by="kubetee-sn90-gamma-funder")
        current = await self.find_exact_hotkey(
            decode_metadata(metadata or row.metadata)["gamma_hotkey"])
        if current is None or current.token != row.token:
            raise ManagingConflict("native key-management update readback failed")
        if metadata is not None and decode_metadata(current.metadata) != metadata:
            raise ManagingConflict("native metadata readback failed")
        if max_budget is not None and exact_units(current.max_budget) != exact_units(max_budget):
            raise ManagingConflict("native max_budget readback failed")
        if blocked is not None and current.blocked is not blocked:
            raise ManagingConflict("native blocked readback failed")
        return current

    async def find_exact_hotkey(self, hotkey: str):
        found = None
        async for row in self._list_team_rows():
            if self._assert_gamma_row(row).get("gamma_hotkey") == hotkey:
                if found is not None:
                    raise ManagingConflict("duplicate exact-hotkey identities")
                found = row
        return found

    async def gamma_identities(self) -> list[dict[str, Any]]:
        """Read the existing Gamma key index without returning customer secrets."""
        rows = []
        async for row in self._list_team_rows():
            _project(row)
            cp = self._assert_gamma_row(row).get("gamma")
            if isinstance(cp, dict) and cp.get("schema") == 1:
                rows.append({"metadata": {"gamma": cp}})
        return rows


    async def reserve(self, hotkey: str, checkpoint: dict[str, Any], permissions: dict[str, Any], secret: str):
        from litellm.proxy._types import GenerateKeyRequest
        from litellm.proxy.management_endpoints.key_management_endpoints import generate_key_fn
        if await self.find_exact_hotkey(hotkey) is not None:
            raise ManagingConflict("identity already reserved")
        # Native key_alias is globally unique and names the stored virtual-key
        # secret. Keep the coldkey visible as prefix, but include exact H so a
        # coldkey's second funded hotkey cannot collide or borrow its credential.
        key_alias = checkpoint["observation_coldkey"] + "-" + hotkey.lower()
        data = GenerateKeyRequest.model_validate({
            "key": secret, "key_alias": key_alias, "max_budget": 0.0,
            "team_id": os.environ.get("KUBETEE_GAMMA_TEAM_ID"),
            "spend": 0.0, "blocked": True, "budget_duration": None,
            "models": permissions["models"], "metadata": {"gamma": checkpoint,
            "gamma_hotkey": hotkey, "gamma_netuid": NETUID, "gamma_network": NETWORK},
            "key_type": "llm_api", **({"object_permission": {"mcp_servers": permissions["mcp_servers"]}}
                                      if permissions.get("mcp_servers") is not None else {}),
        })
        # The full native generate_key_fn is required, not its lower-level
        # helper: the route lifecycle persists and later rotates the virtual
        # key in LiteLLM's configured stored-virtual-keys secret manager.
        response = await generate_key_fn(data=data,
            user_api_key_dict=await self.admin(),
            litellm_changed_by="kubetee-sn90-gamma-funder")
        row = await self.find_exact_hotkey(hotkey)
        if row is None or getattr(response, "token", None) != row.token:
            raise ManagingConflict("native reservation readback failed")
        if not hmac.compare_digest(hashlib.sha256(response.key.encode()).hexdigest(), response.token):
            raise ManagingConflict("native generated secret/hash evidence mismatched")
        if response.token_id != response.token:
            raise ManagingConflict("native generated token id mismatch")
        if row.blocked is not True or exact_units(row.max_budget) != 0:
            raise ManagingConflict("reserved virtual key is usable before proof of credit")
        return row

    async def compare_checkpoint(self, hotkey: str, expected: dict[str, Any] | None,
                                 checkpoint: dict[str, Any], expected_max_budget: str,
                                 *, target_max_budget: str | None = None):
        row = await self.find_exact_hotkey(hotkey)
        if row is None:
            raise ManagingConflict("native identity disappeared")
        metadata = decode_metadata(row.metadata)
        if (metadata.get("gamma") != expected
                or exact_units(row.max_budget) != exact_units(expected_max_budget)):
            raise ManagingConflict("unchanged version required for conditional transition")
        updated_metadata = {**metadata, "gamma": checkpoint}
        if target_max_budget is None:
            if (settled_total(checkpoint) != settled_total(expected)
                    or checkpoint.get("receipt_ids") != (expected or {}).get("receipt_ids")):
                raise ManagingConflict("only a credit may change settled Gamma or its receipts")
            return await self.update(row, metadata=updated_metadata)
        # Credit. max_budget is exactly the settled total before and after, and
        # both the receipt and the allowance travel in one native key update.
        # The preceding read is a precondition check, not a database CAS: the
        # worker's per-hotkey lease is what serializes writers. Because every
        # credit writes the checkpoint and its own total together, a writer
        # that outlives its lease can lose a newer receipt but can never leave
        # more budget on the row than the receipts stored beside it.
        before, after = settled_total(expected), settled_total(checkpoint)
        if exact_units(row.max_budget) != before:
            raise ManagingConflict("native max_budget is not the settled Gamma total; credit refused")
        if after != before + pending_amount(checkpoint, expected):
            raise ManagingConflict("settled total is not previous total + proven Gamma units")
        if exact_units(target_max_budget) != after:
            raise ManagingConflict("target max_budget is not the settled Gamma total")
        native_budget(target_max_budget)  # refuse before writing, not at readback
        # The reservation is blocked with zero budget. Its first proven credit
        # enables it in the same write, so key delivery never has to write the
        # row. Later credits leave ``blocked`` alone: an operator block stays.
        enable = False if before == 0 and row.blocked else None
        return await self.update(row, metadata=updated_metadata,
                                 max_budget=target_max_budget, blocked=enable)

    async def compare_and_checkpoint(self, hotkey: str, expected: dict[str, Any],
                                     checkpoint: dict[str, Any], previous_max_budget: str,
                                     target_max_budget: str):
        return await self.compare_checkpoint(
            hotkey, expected, checkpoint, previous_max_budget,
            target_max_budget=target_max_budget,
        )

    async def evict(self, token: str):
        from litellm.proxy.auth.auth_checks import delete_cache_key_object
        await delete_cache_key_object(token, self.proxy.user_api_key_cache, self.proxy.proxy_logging_obj)

    async def rotate(self, hotkey: str) -> tuple[Any, str]:
        from litellm.proxy._types import RegenerateKeyRequest
        from litellm.proxy.management_endpoints.key_management_endpoints import regenerate_key_fn
        row = await self.find_exact_hotkey(hotkey)
        if row is None:
            raise ManagingConflict("no funded identity to rotate")
        response = await regenerate_key_fn(key=row.token,
            data=RegenerateKeyRequest(key=row.token, key_alias=row.key_alias),
            user_api_key_dict=await self.admin(),
            litellm_changed_by="kubetee-sn90-gamma-funder")
        if response is None or not response.token or not response.token_id:
            raise RuntimeError("native key rotation had no definitive stored-secret result")
        # v1.108.3 sets .token_id to the raw secret's SHA256. There is no
        # query_result/opaque database identity on GenerateKeyResponse. Use
        # only the documented native fields, followed by an API readback.
        expected = response.token
        if response.token_id != expected:
            raise ManagingConflict("native regeneration token id mismatch")
        current = await self.find_exact_hotkey(hotkey)
        if current is None or current.token != expected:
            raise ManagingConflict("regenerated exact-hotkey identity disappeared")
        if decode_metadata(current.metadata) != decode_metadata(row.metadata):
            raise ManagingConflict("regenerated key lost its settled Gamma metadata")
        for attempt in range(20):
            raw = await self.stored_key(current)
            if isinstance(raw, str) and hmac.compare_digest(hashlib.sha256(raw.encode()).hexdigest(), expected):
                return current, raw
            await asyncio.sleep(0.05)
        raise ManagingConflict("native regenerated stored key was not confirmed")

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
        "reconciliation_reference": (decode_metadata(row.metadata).get("gamma") or {}).get("last_spent_reference"),
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

    async def _settled_reference_check(self, hotkey: str, expected_reference: str) -> None:
        readback = await self.key(hotkey)
        if readback.get("row", {}).get("reconciliation_reference") != expected_reference:
            raise ManagingConflict("worker result does not match committed exact-H settlement")

    async def key(self, hotkey_ss58: str = Query(min_length=48, max_length=48),
                  network: Literal["finney"] = "finney", genesis_hash: Literal[GENESIS] = GENESIS,
                  netuid: Literal["90"] = "90") -> dict[str, Any]:
        self.assert_hotkey(hotkey_ss58)
        row = await (await self.keys()).find_exact_hotkey(hotkey_ss58)
        return {"exists": row is not None, "row": None if row is None else _project(row)}

    async def reserve(self, body: ReservationRequest):
        if body.key_alias != body.checkpoint.get("observation_coldkey") + "-" + body.hotkey_ss58.lower():
            raise HTTPException(403, {"error": "exact coldkey/hotkey alias must be observed from finalized chain"})
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
        if (settled_total(body.checkpoint) != settled_total(body.expected_checkpoint)
                or body.checkpoint.get("receipt_ids") != body.expected_checkpoint.get("receipt_ids")):
            raise ManagingConflict("only a credit may change settled Gamma or its receipts")
        row = await (await self.keys()).compare_checkpoint(body.hotkey_ss58,
            body.expected_checkpoint, body.checkpoint, body.previous_max_budget)
        if row is None:
            raise ManagingConflict("conditional write readback failed")
        if exact_units(row.max_budget) != exact_units(body.previous_max_budget):
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
        # max_budget is the settled Gamma total, before and after. Anything else
        # (an operator edit, a lost write) stops crediting until it is repaired.
        if (exact_units(body.previous_max_budget) != settled_total(body.previous_checkpoint)
                or exact_units(body.target_max_budget) != settled_total(cp)):
            raise HTTPException(409, {"error": "native max_budget must equal the settled Gamma total"})
        row = await (await self.keys()).compare_and_checkpoint(body.hotkey_ss58,
            body.previous_checkpoint, cp, body.previous_max_budget, body.target_max_budget)
        if row is None:
            raise ManagingConflict("settlement write did not persist")
        written = decode_metadata(row.metadata).get("gamma")
        if written != cp or exact_units(row.max_budget) != exact_units(body.target_max_budget):
            raise RuntimeError("native credit readback failed")
        if exact_units(row.max_budget) != settled_total(written):
            raise RuntimeError("credited key does not hold exactly its settled Gamma")
        if settled_total(body.previous_checkpoint) == 0 and row.blocked:
            raise RuntimeError("first credit did not enable the reserved key")
        return {"row": _project(row)}

    async def issue(self, hotkey: str, action: str, verification_digest: str,
                    reconciliation_reference: str | None = None) -> dict[str, Any]:
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
                return await self._issue_serialized(hotkey, action, reconciliation_reference)
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
                result_task = asyncio.create_task(self._issue_serialized(hotkey, action, reconciliation_reference))
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

    async def _issue_serialized(self, hotkey: str, action: str, reconciliation_reference: str | None = None) -> dict[str, Any]:
        native = await self.keys()
        selected_token = None
        row = await native.find_exact_hotkey(hotkey)
        if row is None:
            # Rotation can invalidate a cached identity between retries. Check
            # the persisted settled receipt rather than manufacturing another
            # funded identity just to replay an earlier claim.
            if reconciliation_reference is not None and action == "claim":
                # The worker persists the exact settlement checkpoint before it
                # can return that same reference. Do not guess a key from public
                # event data when the native insertion is still unavailable.
                return {"status": "pending", "error": "native credential not yet finalized"}
            raise HTTPException(409, {"error": "no native retention identity"})
        check = decode_metadata(row.metadata).get("gamma") or {}
        reference = check.get("last_spent_reference")
        if exact_units(row.max_budget) <= 0:
            raise HTTPException(409, {"error": "no positive finalized chain settlement"})
        if not isinstance(reference, str) or not reference:
            raise HTTPException(409, {"error": "no signed-chain reconciliation reference"})
        # Never store a raw vk in metadata.
        required_alias = check["observation_coldkey"] + "-" + hotkey.lower()
        if row.key_alias != required_alias:
            # Alias is also the stored-secret lookup name. Do not read another
            # identity's secret and patch its apparent alias after the fact.
            raise HTTPException(409, {"error": "exact-hotkey native credential identity is not established"})
        if check.get("hotkey_ss58", hotkey) != hotkey:
            raise ManagingConflict("settled checkpoint has wrong exact-H identity")
        if reconciliation_reference is not None:
            if reconciliation_reference != reference:
                raise ManagingConflict("worker claim reference is not the native settled receipt")
            if action == "regenerate":
                # The already-settled reference must equal this exact-H row's
                # current native proof. The worker's lease fences rotation;
                # there is no public caller-driven receipt-to-token remap.
                if check.get("last_spent_reference") != reconciliation_reference:
                    raise ManagingConflict("settled proof belongs to another exact-hotkey identity")
        # The first credit enables the key in the same write as its budget.
        # Delivery never writes the row: a native key update rewrites the whole
        # metadata column from its own earlier read, so an unblock here could
        # roll back a credit landing at the same moment. A funded key that is
        # blocked was blocked by an operator; do not hand it out or undo that.
        if row.blocked:
            raise HTTPException(409, {"error": "funded key is blocked; operator review required"})
        if action == "regenerate":
            # Keep the durable proof on the new token while the old token moves
            # to LiteLLM DeletedVerificationToken. preserves paid credit and
            # permits an interrupted regeneration to be retried safely.
            funding = decode_metadata(row.metadata).get("hotkey_funding") or {}
            previous = copy.deepcopy(funding)
            funding["reconciliation_reference"] = reconciliation_reference or reference
            funding["receipt"] = check.get("last_spent_extra") or reference
            row, raw = await native.rotate(hotkey)
            if row is None or row.blocked:
                raise ManagingConflict("regenerated native key is not a funded active key")
        else:
            selected_token = row.token
            try:
                raw = await native.stored_key(row)
            except HTTPException as exc:
                if exc.status_code == 401:
                    return {"status": "pending", "error": "native credential not yet finalized"}
                raise
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
        return {"status": "provisioned", "has_positive_chain_settlement": True,
                "max_budget": str(row.max_budget), "spend": usage_text(row.spend),
                "remaining_credit": format(
                    Decimal(units_text(exact_units(row.max_budget))) - Decimal(usage_text(row.spend)), "f"),
                "reconciliation_reference": reference,
                "models": list(row.models or []), "receipts": check.get("receipt_ids", []),
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
    # Raw-key issue is deliberately absent from the worker HTTP surface. Raw
    # credentials leave only the in-process connect_public_claims callback after
    # exact-hotkey settlement is rechecked, creating no second authority.
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
