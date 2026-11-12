"""Exact-hotkey Gamma claim routes.

The gateway verifies possession of H. A separately authenticated worker alone
reads finalized chain state and applies max_budget through LiteLLM management.
It supplies a durable fencing context for each key issue/rotate. The gateway
never exposes budget mutation publicly, believes a customer amount, or stores chain credit independently.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import json
import secrets
import ipaddress
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Protocol
from uuid import UUID, uuid4

import bittensor as bt
from bittensor.settings import FINNEY_GENESIS_HASH
from bittensor_core import Keypair
from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.routing import APIRoute
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.exceptions import ExceptionMiddleware
from starlette.middleware.errors import ServerErrorMiddleware
from starlette.routing import Mount
from pydantic import BaseModel, ConfigDict, Field

LOG = logging.getLogger(__name__)
NETWORK = "finney"
GENESIS = FINNEY_GENESIS_HASH
NETUID = 90
MAX_TTL = 300
RETRY_SECONDS = 6
MAX_WAIT_SECONDS = 45
MAX_CHALLENGES = 4096
ACTIONS = {"claim", "regenerate", "status"}
PENDING_REASONS = {
    "chain_finalizing", "spend_in_flight", "spend_final_credit_pending",
    "credit_readback_pending", "worker_unavailable", "unfunded",
    "service_unavailable", "proxy_eligibility_changed",
}


class ChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hotkey_ss58: str = Field(min_length=48, max_length=48)
    action: str
    netuid: int = NETUID


class SignedChallenge(BaseModel):
    model_config = ConfigDict(extra="forbid")
    challenge_id: UUID
    signature: str = Field(pattern=r"^[0-9a-fA-F]{128}$")


class GammaWorker(Protocol):
    native_credit_callback_configured: bool
    trusted_proxy_ips: tuple[str, ...]
    ready: bool

    async def reconcile(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]: ...
    async def status(self, hotkey_ss58: str) -> tuple[int, dict[str, Any]]: ...
    async def claim(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]: ...
    async def rotate(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]: ...


class PrivateWorkerResponse:
    """Gateway-private bridge: separate TEE worker, then native key issuance.

    This adapter has no chain or spender authority. Production injection supplies
    only authenticated herringbone sidecar clients; disabled configuration stays
    fail-closed through UnavailableWorker. Its chain reconciliation never returns
    raw sk; only the second intentionally private response can deliver one.
    """
    native_credit_callback_configured = True
    trusted_proxy_ips: tuple[str, ...] = ()
    ready = True

    def __init__(self, chain_worker: Any, native_response: Any = None, worker_headers: dict[str, str] | None = None):
        from kubetee_gamma_private_mtls import InProcessIssueClient
        if chain_worker is None or not isinstance(native_response, InProcessIssueClient):
            raise RuntimeError("raw-key issuance requires the measured in-process private client")
        self.worker_http = chain_worker
        self.native_http = native_response
        self.worker_headers = worker_headers or {}

    async def _worker(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        response = await self.worker_http.post("/internal/v1/reconcile", json={
            "network": NETWORK, "genesis_hash": GENESIS, "netuid": NETUID,
            "hotkey_ss58": body["hotkey_ss58"], "action": body["action"],
            "verified_challenge_digest": body["verified_challenge_digest"],
        }, headers=self.worker_headers)
        return self._result(response)

    @staticmethod
    def _result(response: Any) -> tuple[int, dict[str, Any]]:
        try:
            result = response.json()
            if isinstance(result, dict) and isinstance(result.get("detail"), dict):
                result = result["detail"]
        except (ValueError, TypeError):
            result = {}
        if response.status_code in (200, 202) and result.get("status") == "pending" and result.get("reason") == "worker_unavailable":
            return 202, {"status": "pending", "reason": "worker_unavailable", "retry_after_seconds": RETRY_SECONDS}
        if response.status_code == 200:
            # FastAPI serializes the worker's PublicResult with HTTP 200 even
            # when its semantic status is pending. Translate that validated
            # pending payload to the public bounded-wait contract.
            return (202, result) if result.get("status") == "pending" else (200, result)
        if response.status_code in (401, 403):
            reason = result.get("reason")
            if result.get("status") == "ineligible" and isinstance(reason, str):
                return 403, {"status": "ineligible", "reason": reason}
        if response.status_code == 422 and result.get("status") == "ineligible":
            reason = result.get("reason")
            if isinstance(reason, str):
                return 422, {"status": "ineligible", "reason": reason}
        return 503, {"status": "retryable_error"}

    async def claim(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        return await self._worker_action(body)

    async def rotate(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        return await self._worker_action(body)

    async def reconcile(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        return await self._worker(body)

    async def _worker_action(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        code, result = await self._worker(body)
        if code != 200 or result.get("status") != "funded":
            LOG.info("Gamma worker returned HTTP %s status %s; private issue withheld", code, result.get("status") if isinstance(result, dict) else None)
            return code, result
        # The worker result is advisory. The mTLS-pinned native callback re-reads
        # the key and requires settled positive credit before issuance.
        try:
            issued = await self.native_http.issue(
                body["hotkey_ss58"], body["action"], body["verified_challenge_digest"],
            )
        except Exception:
            # Funding is retained in LiteLLM. It is safer to return bounded
            # pending-and-retry than discard a successful reconciliation solely
            # because credential delivery encountered a transient DB conflict.
            LOG.exception("Measured in-process Gamma key issuance failed")
            return 202, {"status": "pending", "reason": "spend_final_credit_pending",
                         "retry_after_seconds": RETRY_SECONDS}
        if isinstance(issued, dict) and issued.get("status") == "provisioned":
            return 200, issued
        if isinstance(issued, dict) and issued.get("status") == "pending":
            return 202, issued
        return 503, {"status": "retryable_error"}

    async def status(self, hotkey_ss58: str) -> tuple[int, dict[str, Any]]:
        row_data = await self.native_http.management.key(hotkey_ss58)
        row = row_data.get("row")
        checkpoint = (row.get("metadata", {}).get("gamma") or {}) if isinstance(row, dict) else {}
        if row is None:
            return 403, {"status": "ineligible", "reason": "not_provisioned"}
        budget, spent = Decimal(str(row["max_budget"])), Decimal(str(row["spend"]))
        if not budget.is_finite() or not spent.is_finite() or spent < 0:
            raise ValueError("invalid native money in private status")
        return 200, {"status": "provisioned", "max_budget": str(budget),
            "spend": str(spent), "remaining_credit": str(budget - spent),
            "reconciliation_reference": checkpoint.get("last_spent_reference")}


class UnavailableWorker:
    """Fail closed: neither an empty key nor fabricated native credit."""
    native_credit_callback_configured = False
    trusted_proxy_ips: tuple[str, ...] = ()
    ready = False

    async def reconcile(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        del body
        return 503, {"status": "retryable_error"}

    async def status(self, hotkey_ss58: str) -> tuple[int, dict[str, Any]]:
        del hotkey_ss58
        return 503, {"status": "retryable_error"}

    async def claim(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        del body
        return 503, {"status": "retryable_error"}

    async def rotate(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        del body
        return 503, {"status": "retryable_error"}


class MemoryAuthority:
    """Synthetic atomic challenge store; real stores require durable worker fencing."""

    def __init__(self):
        self.entries: dict[str, dict[str, Any]] = {}
        self.nonces: dict[str, float] = {}
        self.lock = asyncio.Lock()

    async def insert_nonce(self, hotkey_ss58: str, nonce: str, ttl: int) -> bool:
        key = _nonce_digest(hotkey_ss58, nonce)
        now = time.monotonic()
        async with self.lock:
            self.nonces = {key: expiry for key, expiry in self.nonces.items() if expiry > now}
            if key in self.nonces:
                return False
            self.nonces[key] = now + ttl
            return True

    async def insert_challenge(self, challenge_id: str, entry: dict[str, Any], ttl: int) -> None:
        del ttl
        async with self.lock:
            if len(self.entries) >= MAX_CHALLENGES:
                raise RuntimeError("challenge capacity exhausted")
            self.entries[challenge_id] = entry

    async def consume(self, challenge_id: str, expected_action: str,
                      signature: str, source_ip: str) -> dict[str, Any]:
        async with self.lock:
            entry = self.entries.get(challenge_id)
            if not entry or entry["used"]:
                raise HTTPException(401, {"status": "ineligible", "reason": "invalid_or_replayed_challenge"})
            if entry["expires"] <= utc_now():
                raise HTTPException(401, {"status": "ineligible", "reason": "expired_challenge"})
            if entry["action"] != expected_action:
                raise HTTPException(403, {"status": "ineligible", "reason": "action_mismatch"})
            if entry["source_ip"] != source_ip:
                raise HTTPException(403, {"status": "ineligible", "reason": "challenge_source_mismatch"})
            if not _standard_signature_verified(entry["message"], signature, entry["hotkey_ss58"]):
                raise HTTPException(403, {"status": "ineligible", "reason": "invalid_signature"})
            entry["used"] = True
            return dict(entry)


class RedisAuthority:
    """Atomic claim challenges on LiteLLM's native async Redis client."""

    def __init__(self, cache: Any):
        self.cache = cache
        self.consume_script = cache.register_script("""
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local entry = cjson.decode(raw)
if entry.used then return 0 end
if entry.message_digest ~= ARGV[1] or entry.source_ip ~= ARGV[2] or entry.action ~= ARGV[3] or entry.expires <= tonumber(ARGV[4]) then return 0 end
entry.used = true
redis.call('SET', KEYS[1], cjson.encode(entry), 'KEEPTTL')
return 1
""")
        self.local_lock = asyncio.Lock()

    @staticmethod
    def _key(challenge_id: str) -> str:
        return "kubetee:gamma:challenge:v1:" + challenge_id

    async def insert_nonce(self, hotkey_ss58: str, nonce: str, ttl: int) -> bool:
        return await self.cache.set(
            "kubetee:gamma:nonce:v1:" + _nonce_digest(hotkey_ss58, nonce), "1", ex=ttl, nx=True,
        )

    async def insert_challenge(self, challenge_id: str, entry: dict[str, Any], ttl: int) -> None:
        value = json.dumps(dict(entry, expires=entry["expires"].timestamp()), separators=(",", ":"))
        inserted = await self.cache.set(self._key(challenge_id), value, ex=ttl, nx=True)
        if inserted is not True:
            raise RuntimeError("challenge reservation failed")

    async def consume(self, challenge_id: str, expected_action: str,
                      signature: str, source_ip: str) -> dict[str, Any]:
        import ipaddress
        ipaddress.ip_address(source_ip)
        key = self._key(challenge_id)
        # Consume once, preserving creation TTL; the client owns credentials
        # and Sentinel routing. Challenge keys have no cache_namespace prefix.
        # This script is fixed application-owned code, never request input.
        async with self.local_lock:
            serialized = await self.cache.get(key)
            if not isinstance(serialized, (str, bytes)):
                raise HTTPException(401, {"status": "ineligible", "reason": "invalid_or_replayed_challenge"})
            try:
                stored = json.loads(serialized)
                if not isinstance(stored, dict):
                    raise ValueError("challenge is not an object")
                if type(stored["expires"]) not in (int, float):
                    raise ValueError("invalid challenge expiry")
                required = {"used", "challenge_id", "action", "source_ip", "message", "hotkey_ss58", "message_digest"}
                if not required <= stored.keys() or any(not isinstance(stored[field], str) for field in required - {"used"}):
                    raise ValueError("missing challenge identity")
                if type(stored["used"]) is not bool:
                    raise ValueError("malformed challenge usage")
                entry = stored
                entry["expires"] = datetime.fromtimestamp(stored["expires"], timezone.utc)
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError, TypeError, KeyError, OverflowError):
                raise HTTPException(401, {"status": "ineligible", "reason": "invalid_or_replayed_challenge"}) from None
            if entry["used"] or entry["challenge_id"] != challenge_id:
                raise HTTPException(401, {"status": "ineligible", "reason": "invalid_or_replayed_challenge"})
            if entry["action"] != expected_action:
                raise HTTPException(403, {"status": "ineligible", "reason": "action_mismatch"})
            if entry["source_ip"] != source_ip:
                raise HTTPException(403, {"status": "ineligible", "reason": "challenge_source_mismatch"})
            # The challenge-issuing side has already authenticated exact-H;
            # this side verifies a standard sr25519 signature for that same
            # stored address then the Lua script checks the message digest.
            if entry["message_digest"] != hashlib.sha256(entry["message"].encode()).hexdigest():
                raise HTTPException(403, {"status": "ineligible", "reason": "invalid_challenge_context"})
            if not _standard_signature_verified(entry["message"], signature, entry["hotkey_ss58"]):
                raise HTTPException(403, {"status": "ineligible", "reason": "invalid_signature"})
            consumed = await self.consume_script(
                keys=[key], args=[hashlib.sha256(entry["message"].encode()).hexdigest(),
                source_ip, expected_action, str(utc_now().timestamp())],
            )
            entry["used"] = True
            if consumed != 1:
                raise HTTPException(401, {"status": "ineligible", "reason": "invalid_or_replayed_challenge"})
            return entry


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _nonce_digest(hotkey_ss58: str, nonce: str) -> str:
    return hashlib.sha256(hotkey_ss58.encode() + b"\0" + nonce.encode()).hexdigest()


def _verify(message: str, signature: str, hotkey_ss58: str, verifier=None) -> bool:
    if verifier is None:
        try:
            return Keypair(
                ss58_address=hotkey_ss58, crypto_type=bt.CRYPTO_SR25519,
            ).verify(message.encode(), bytes.fromhex(signature))
        except (ValueError, TypeError):
            return False
    return verifier(message, signature, hotkey_ss58)


def _standard_signature_verified(message: str, signature: str, hotkey_ss58: str) -> bool:
    """Explicit trusted scheme: no guessed hash framing or signature-selected crypto."""
    return _verify(message, signature, hotkey_ss58)


def positive_credit(value: object) -> bool:
    try:
        record = value or {}
        budget = Decimal(str(record["max_budget"]))
        spend = Decimal(str(record["spend"]))
        remaining = Decimal(str(record["remaining_credit"]))
        return (budget.is_finite() and spend.is_finite() and remaining.is_finite()
                and budget > 0 and spend >= 0 and remaining > 0
                and budget - spend == remaining)
    except (InvalidOperation, KeyError, TypeError, ValueError):
        return False


def public_projection(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("malformed worker result")
    status = value.get("status")
    if status == "ineligible":
        reason = value.get("reason")
        if not isinstance(reason, str) or len(reason) > 80:
            raise ValueError("unsafe worker eligibility outcome")
        return {"status": "ineligible", "reason": reason}
    if status in {"provisioned", "funded"} and positive_credit(value):
        return {
            "status": "funded",
            "remaining_credit": value["remaining_credit"],
            "max_budget": value["max_budget"],
            "spend": value["spend"],
        }
    if status == "pending" and value.get("reason") in PENDING_REASONS:
        retry = max(RETRY_SECONDS, int(value.get("retry_after_seconds", RETRY_SECONDS)))
        correlation = value.get("correlation_id") or ""
        if not isinstance(correlation, str) or len(correlation) > 80:
            raise ValueError("unsafe correlation identifier")
        return {"status": "pending", "reason": value["reason"],
                "retry_after_seconds": retry, "correlation_id": correlation}
    if status == "retryable_error":
        return {"status": "retryable_error", "reason": "temporary_failure"}
    raise ValueError("unknown worker result")


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


def _typed_response(code: int, result: object) -> JSONResponse:
    try:
        body = public_projection(result)
    except (ValueError, KeyError, TypeError):
        LOG.error("Invalid worker response projection for status %s", code, exc_info=True)
        code = 503
        body = {"status": "retryable_error", "reason": "temporary_failure"}
    if code == 202:
        return JSONResponse(body, status_code=202, headers={
            "Retry-After": str(body.get("retry_after_seconds", RETRY_SECONDS)),
            "Cache-Control": "no-store",
        })
    return JSONResponse(body, status_code=code, headers={"Cache-Control": "no-store"})


class RateLimit:
    def __init__(self):
        self.values: dict[str, float] = {}
        self.lock = asyncio.Lock()

    async def hit(self, key: str, seconds: float) -> bool:
        now = time.monotonic()
        async with self.lock:
            self.values = {key: then for key, then in self.values.items() if now - then < 60}
            if now - self.values.get(key, -100) < seconds:
                return False
            self.values[key] = now
            return True


class KubeTEEGammaClaimHandler:
    """The exact signed public protocol; no amount/budget input anywhere."""

    def __init__(self, worker: GammaWorker, *, authority: Any = None,
                 challenge_ttl_seconds: int = MAX_TTL, chain_network: str = NETWORK,
                 wait_seconds: int = MAX_WAIT_SECONDS):
        if chain_network != NETWORK:
            raise ValueError("only Finney is supported")
        if not 5 <= challenge_ttl_seconds <= MAX_TTL:
            raise ValueError("challenge TTL must be between 5 and 300 seconds")
        if not 1 <= wait_seconds <= MAX_WAIT_SECONDS:
            raise ValueError("wait must be bounded")
        if worker.trusted_proxy_ips:
            raise ValueError("production enablement remains gated on measured shared challenge store and worker fencing")
        self.worker = worker
        self.authority = authority
        self.challenge_ttl = challenge_ttl_seconds
        self.wait_seconds = wait_seconds
        self.challenge_limit = RateLimit()
        self.signed_limit = RateLimit()

    async def close(self):
        """Close only clients opened by the measured claim bridge."""
        resources = (self.authority.cache if isinstance(self.authority, RedisAuthority) else None,
                     getattr(self.worker, "native_http", None), getattr(self.worker, "worker_http", None))
        for resource in resources:
            if resource is not None and callable(getattr(resource, "aclose", None)):
                await resource.aclose()

    def source_ip(self, request: Request) -> str:
        if request.client is None:
            return ""
        if request.client.host in self.worker.trusted_proxy_ips:
            forwarded = request.headers.get("x-forwarded-for", "").split(",", 1)[0].strip()
            try:
                ipaddress.ip_address(forwarded)
                return forwarded
            except ValueError:
                return request.client.host
        return request.client.host

    async def challenge(self, body: ChallengeRequest, client_ip: str = "testclient",
                        request: Request | None = None) -> dict[str, Any]:
        del request
        if body.action not in ACTIONS or body.netuid != NETUID:
            raise HTTPException(400, {"status": "ineligible", "reason": "unsupported_scope"})
        try:
            Keypair(ss58_address=body.hotkey_ss58, crypto_type=bt.CRYPTO_SR25519)
        except Exception as error:
            raise HTTPException(400, {"status": "ineligible", "reason": "invalid_hotkey"}) from error
        if not await self.challenge_limit.hit(client_ip + ":" + body.hotkey_ss58, 6):
            raise HTTPException(429, {"status": "retryable_error"})
        if self.authority is None:
            raise HTTPException(503, {"status": "retryable_error"})
        nonce = secrets.token_hex(32)
        if not await self.authority.insert_nonce(body.hotkey_ss58, nonce, 86400):
            raise RuntimeError("nonce collision")
        identifier = str(uuid4())
        now = utc_now()
        expires = now + timedelta(seconds=self.challenge_ttl)
        message = json.dumps({
            "scheme": "kubetee-gamma-challenge/v1", "network": NETWORK,
            "chain_genesis_hash": GENESIS, "netuid": NETUID,
            "hotkey_ss58": body.hotkey_ss58, "signer_ss58": body.hotkey_ss58,
            "signature_generation": 1,
            "action": body.action, "challenge_id": identifier,
            "domain": "kubetee.ai", "nonce": nonce,
            "issued_at": now.isoformat(), "expires_at": expires.isoformat(),
        }, separators=(",", ":"))
        await self.authority.insert_challenge(identifier, {
            "challenge_id": identifier, "message": message,
            "hotkey_ss58": body.hotkey_ss58, "action": body.action,
            "source_ip": client_ip, "expires": expires, "used": False,
            "message_digest": hashlib.sha256(message.encode()).hexdigest(),
        }, self.challenge_ttl)
        return {"challenge_id": identifier, "message": message, "expires_at": expires.isoformat()}

    async def _signed(self, body: SignedChallenge, action: str, request: Request) -> dict[str, Any]:
        if not await self.signed_limit.hit(self.source_ip(request) + ":" + str(body.challenge_id), 10):
            raise HTTPException(429, {"status": "retryable_error"})
        if self.authority is None:
            raise HTTPException(503, {"status": "retryable_error"})
        return await self.authority.consume(
            str(body.challenge_id), action, body.signature, self.source_ip(request),
        )

    async def _reconcile(self, entry: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        """One worker operation must keep settlement/key delivery indivisible.

        Concurrent independently-signed requests join the same H's durable lock.
        The worker returns the established key for a repeat claim, never a
        second budget or an extra key for one finalized settlement.
        """
        if not self.worker.ready:
            return 202, {"status": "pending", "reason": "worker_unavailable",
                         "retry_after_seconds": RETRY_SECONDS}
        request = {
            "network": NETWORK, "chain_genesis_hash": GENESIS, "netuid": NETUID,
            "hotkey_ss58": entry["hotkey_ss58"], "action": entry["action"],
            "verified_challenge_digest": hashlib.sha256(entry["message"].encode()).hexdigest(),
        }
        operation = self.worker.rotate if entry["action"] == "regenerate" else self.worker.claim
        try:
            code, result = await asyncio.wait_for(operation(request), self.wait_seconds)
            return (202, result) if code == 202 else (code, result)
        except (TimeoutError, asyncio.TimeoutError):
            return 202, {"status": "pending", "reason": "spend_final_credit_pending"}

    def register(self, app: Any) -> FastAPI:
        if not self.worker.native_credit_callback_configured:
            raise RuntimeError("management-only credit callback is not configured")
        # A mounted child owns its exception handlers, not the entire gateway.
        # The root path is intentional: public endpoint paths must not change.
        # Disabling its docs avoids a competing default root OpenAPI schema.
        gamma_app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
        app.state.kubetee_gamma_handler = self
        app.state.kubetee_gamma_worker = self.worker
        gamma_app.state.kubetee_gamma_handler = self
        gamma_app.state.kubetee_gamma_worker = self.worker
        # Delay creation of the mount's wrapper so it observes handlers registered
        # handlers registered below and the parent remains untouched.
        async def internal_error(_request: Request, error: Exception):
            LOG.exception("Gamma public claim handler failure")
            return _typed_response(503, {"status": "retryable_error"})

        mount = Mount("", app=ServerErrorMiddleware(
            ExceptionMiddleware(gamma_app), handler=internal_error,
        ))
        app.routes.append(mount)

        @gamma_app.exception_handler(HTTPException)
        async def http_error(_request: Request, error: HTTPException):
            return _typed_response(error.status_code, error.detail)

        @gamma_app.exception_handler(RequestValidationError)
        async def validation_error(request: Request, error: RequestValidationError):
            unknown = any(item.get("type") == "extra_forbidden" for item in error.errors())
            unsigned_status = request.url.path.endswith("/status")
            return JSONResponse({
                "status": "ineligible",
                "reason": "signature_required" if unsigned_status else "amounts_not_accepted" if unknown else "invalid_request",
            }, status_code=401 if unsigned_status else 422, headers={"Cache-Control": "no-store"})


        @gamma_app.post("/v1/gamma/challenge")
        async def public_challenge(body: ChallengeRequest, request: Request):
            return await self.challenge(body, self.source_ip(request))

        async def key_response(entry: dict[str, Any]):
            try:
                code, result = await self._reconcile(entry)
                if code == 200:
                    return JSONResponse(validate_claimed_result(
                        result, first_claim=entry["action"] == "claim",
                    ), headers={"Cache-Control": "no-store"})
                return _typed_response(code, result)
            except (ValueError, KeyError, TypeError):
                LOG.error("Gamma final key response rejected internal data", exc_info=True)
                return _typed_response(503, {"status": "retryable_error"})

        @gamma_app.post("/v1/gamma/key/claim")
        async def public_claim(body: SignedChallenge, request: Request):
            return await key_response(await self._signed(body, "claim", request))

        @gamma_app.post("/v1/gamma/key/regenerate")
        async def public_regenerate(body: SignedChallenge, request: Request):
            return await key_response(await self._signed(body, "regenerate", request))

        @gamma_app.post("/v1/gamma/status")
        async def public_status(body: SignedChallenge, request: Request):
            entry = await self._signed(body, "status", request)
            if not self.worker.ready:
                return _typed_response(503, {"status": "retryable_error"})
            try:
                code, result = await asyncio.wait_for(
                    self.worker.status(entry["hotkey_ss58"]), self.wait_seconds,
                )
            except (TimeoutError, asyncio.TimeoutError):
                return _typed_response(503, {"status": "retryable_error"})
            return _typed_response(code, result)
