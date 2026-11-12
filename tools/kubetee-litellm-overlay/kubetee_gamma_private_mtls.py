"""Verified mTLS-only Gamma callbacks in the ONE TEE gateway container.

Granian's ASGI scope has no peer-certificate extension. Never expose an
unverified HTTP-header bridge on its public listener. When explicitly enabled,
this separate private Uvicorn listener (4001, ClusterIP-only) uses CERT_REQUIRED
and injects only its verified socket DER into the existing management handler.
No sidecar, no master credential, no public management auth bypass.
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import os
import ssl
import threading
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from uvicorn import Config, Server
from uvicorn.protocols.http import h11_impl

import kubetee_gamma_management


async def reject(scope, receive, send, code=403):
    return await JSONResponse({"detail": {"status": "ineligible", "reason": "private callback mTLS required"}},
                             status_code=code)(scope, receive, send)


class NativeLoopDispatcher:
    """Prisma and LiteLLM Redis belong to the pre-server/main event loop.

    The production LiteLLM server is Granian, not Uvicorn. its lifespan loop
    therefore cannot be found by inspecting the private Uvicorn thread. Record
    LiteLLM's own running loop during initialization and return the entire
    private ASGI operation to it; no native client is moved between loops.
    """
    def __init__(self, app, service):
        self.app = app
        self.service = service

    async def __call__(self, scope, receive, send):
        if scope["type"] not in {"http", "websocket"}:
            return await self.app(scope, receive, send)
        owner = getattr(self.service, "owner_loop", None)
        if owner is None or owner is asyncio.get_running_loop():
            return await self.app(scope, receive, send)
        if owner.is_closed():
            raise RuntimeError("LiteLLM native owning event loop is closed")
        operation = asyncio.run_coroutine_threadsafe(
            self.app(scope, receive, send), owner
        )
        try:
            return await asyncio.wrap_future(operation)
        except BaseException:
            operation.cancel()
            raise


class DelegatingPeerMiddleware:
    """Identity comes from the verified TLS socket, never an external proof header."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            allowed = scope["path"].startswith(("/internal/v1/gamma/", "/internal/v1/ready"))
            transport = scope.get("extensions", {}).get("transport")
            tls = transport.get_extra_info("ssl_object") if transport is not None else None
            peer = tls.getpeercert(True) if tls is not None else None
            if not allowed or not isinstance(peer, bytes) or not peer:
                return await reject(scope, receive, send)
            headers = [(key, value) for key, value in scope["headers"]
                       if key not in {b"x-kubetee-worker-cert-der", b"x-kubetee-worker-proof"}]
            headers.append((b"x-kubetee-worker-cert-der", base64.b64encode(peer)))
            scope = {**scope, "headers": headers}
        return await self.app(scope, receive, send)


class PrivateTransportCycle(h11_impl.RequestResponseCycle):
    """Exposes only the server-created transport to measured ASGI middleware."""
    async def run_asgi(self, app):
        extensions = dict(self.scope.get("extensions", {}))
        extensions["transport"] = self.transport
        self.scope["extensions"] = extensions
        return await super().run_asgi(app)


class PrivateTransportProtocol(h11_impl.H11Protocol):
    """Pass transport explicitly in Uvicorn's current constructor interface."""
    def handle_events(self):
        original = h11_impl.RequestResponseCycle
        # Both variants forward every positional or keyword argument; Uvicorn's
        # current no-cycle-attribute implementation is also supported.
        h11_impl.RequestResponseCycle = lambda *args, **kwargs: PrivateTransportCycle(*args, **kwargs)
        try:
            return super().handle_events()
        finally:
            h11_impl.RequestResponseCycle = original


class InProcessIssueClient:
    """Narrow raw-key issuance only inside the measured gateway process.

    The separate mTLS worker can verify funding and request checkpoint CAS but
    cannot obtain a raw customer virtual-key credential. This is deliberately
    not a generic HTTP transport or a secret-returning private endpoint.
    """
    def __init__(self, management):
        if not isinstance(management, kubetee_gamma_management.GammaManagement):
            raise TypeError("native Gamma management service required")
        self.management = management

    async def issue(self, hotkey: str, action: str, verification_digest: str,
                    reconciliation_reference: str | None = None):
        return await self.management.issue(hotkey, action, verification_digest,
                                           reconciliation_reference=reconciliation_reference)


def create_private_application(service) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.kubetee_gamma_private_callback = True
    app.state.kubetee_gamma_private_management = service
    app.add_middleware(DelegatingPeerMiddleware)

    @app.exception_handler(HTTPException)
    async def typed_error(request, error):
        if isinstance(error.detail, dict):
            return JSONResponse({"detail": error.detail}, status_code=error.status_code)
        return JSONResponse({"detail": {"status": "ineligible", "reason": str(error.detail)}}, status_code=error.status_code)

    service.proxy_ip = "127.0.0.1"  # transport DER, not IP, authenticates
    kubetee_gamma_management.installed_router(app, service)
    return app


def create_private_listener(settings: dict[str, str] | None = None):
    """Start explicitly enabled callback listener; absent config is fail-closed."""
    env = dict(os.environ if settings is None else settings)
    if env.get("KUBETEE_GAMMA_ENABLED") not in {"1", "true"}:
        return None
    if env.get("KUBETEE_GAMMA_MTLS_BOOTSTRAP_READY") != "gateway-leaf-pin-ok":
        raise RuntimeError("worker and gateway mTLS certificate fingerprints required")
    names = ("CA", "CERT", "KEY")
    paths = [env.get("KUBETEE_GAMMA_MTLS_" + name, "") for name in names]
    if any(not Path(path).is_file() for path in paths):
        raise RuntimeError("private mTLS certificate files required")
    with open(paths[1], "r", encoding="utf-8") as cert:
        der = ssl.PEM_cert_to_DER_cert(cert.read())
    if hashlib.sha256(der).hexdigest() != env.get("KUBETEE_GAMMA_MTLS_CERT_SHA256", ""):
        raise RuntimeError("private gateway TLS fingerprint mismatch")
    # Inbound mTLS presents the worker's outbound CLIENT certificate. Never
    # confuse it with the worker's serverAuth certificate pinned by our own
    # outbound client at connect_public_claims().
    service = kubetee_gamma_management.GammaManagement(
        certificate_fingerprint=env["KUBETEE_GAMMA_WORKER_CLIENT_CERT_SHA256"],
        proxy_ip="127.0.0.1", models=env["KUBETEE_GAMMA_MODELS"].split(","),
        mcp_servers=[name for name in env.get("KUBETEE_GAMMA_MCP_SERVERS", "").split(",") if name] or None,
    )
    app = create_private_application(service)
    public_address = env.get("KUBETEE_GAMMA_GATEWAY_PUBLIC_ADDRESS", "")
    if public_address not in {"https://llm.kubetee.ai", ""}:
        raise RuntimeError("invalid public address")
    app.state.kubetee_gamma_private_management = service
    app.state.kubetee_gamma_mtls_material = paths
    private_app = NativeLoopDispatcher(app, service)
    from litellm.proxy.proxy_server import app as public_app
    public_app.state.kubetee_gamma_private_management = service
    configuration = Config(private_app, host="0.0.0.0", port=int(env.get("KUBETEE_GAMMA_MTLS_PORT", "4001")),
        http="kubetee_gamma_private_mtls:PrivateTransportProtocol", timeout_keep_alive=5,
        log_level="info", ssl_ca_certs=paths[0], ssl_certfile=paths[1], ssl_keyfile=paths[2],
        ssl_cert_reqs=ssl.CERT_REQUIRED)
    # Bind on LiteLLM's event loop in its async lifespan, then only schedule
    # the already listening Uvicorn server. A thread cannot bind reliably
    # before this async startup hook connects the in-process native bridge.
    import socket as socket_module
    listener = socket_module.socket()
    listener.setsockopt(socket_module.SOL_SOCKET, socket_module.SO_REUSEADDR, 1)
    listener.bind((configuration.host, configuration.port))
    listener.set_inheritable(False)
    server = Server(configuration)
    thread = threading.Thread(target=server.run, args=([listener],), name="kubetee-gamma-private-mtls", daemon=True)
    thread._gamma_service = service
    thread._gamma_server = server
    thread._gamma_listener = listener
    return thread


def start_private_listener(settings: dict[str, str] | None = None):
    thread = create_private_listener(settings)
    if thread is not None:
        thread._gamma_service.owner_loop = asyncio.get_running_loop()
        thread.start()
    return thread


async def connect_public_claims():
    """After Prisma: TLS-pin both private hops; expose ONLY public customer claims."""
    import httpx
    from litellm.proxy import proxy_server
    import kubetee_gamma_claim as claim
    if os.environ.get("KUBETEE_GAMMA_PRIVATE_MANAGEMENT_READY") != "1":
        raise RuntimeError("private mtls is required before any key bridges")
    root = str(Path(os.environ["KUBETEE_GAMMA_MTLS_CA"]).parent)
    trust = ssl.create_default_context(cafile=os.path.join(root, "ca.pem"))
    client_cert = os.environ.get("KUBETEE_GAMMA_MTLS_CLIENT_CERT", os.path.join(root, "client.pem"))
    client_key = os.environ.get("KUBETEE_GAMMA_MTLS_CLIENT_KEY", os.path.join(root, "client.key"))
    trust.load_cert_chain(client_cert, client_key)
    service = getattr(proxy_server.app.state, "kubetee_gamma_private_management", None)
    # Credential delivery belongs only to the in-process narrow issue wrapper,
    # never through the separately attested worker's external HTTP API.
    service = getattr(proxy_server.app.state, "kubetee_gamma_private_management", None)
    if service is None:
        raise RuntimeError("native private management identity missing at claim bridge setup")
    native_delivery = InProcessIssueClient(service)
    # This client is captured by the long-lived claim handler. A one-time
    # pre-connect cannot pin a later pooled TLS connection: put peer evidence
    # on every actual HTTP response instead. The KubeTEE worker Server leaf is
    # the fourth, directional certificate (not the private listener client).
    # It is delivered to this container only after independent KBS policy
    # approval, and never compared to a public key or header assertion.
    from urllib.parse import urlsplit
    worker_url = os.environ["KUBETEE_GAMMA_WORKER_URL"]
    worker_pin = os.environ.get("KUBETEE_GAMMA_WORKER_CERT_SHA256", "")
    if len(worker_pin) != 64 or any(c not in "0123456789abcdef" for c in worker_pin):
        raise RuntimeError("verified worker server leaf pin required")
    from kubetee_gamma_tls import PinningAsyncTransport

    worker_http = httpx.AsyncClient(
        transport=PinningAsyncTransport(
            httpx.AsyncHTTPTransport(verify=trust),
            hostname=urlsplit(worker_url).hostname,
            fingerprint=worker_pin,
        ),
        base_url=worker_url,
        timeout=60,
    )
    from kubetee_gamma_transport import redis_production_settings
    redis_config = redis_production_settings(os.environ.get("KUBETEE_GAMMA_REDIS_URL", ""))
    from kubetee_gamma_transport import native_async_redis
    # Claim consumption and key issuance share this bounded loop-scoped client.
    # Sentinel has distinct monitor credentials; the native pool-injection path
    # preserves them rather than silently inheriting data-node username/TLS.
    issuance_lease = native_async_redis(redis_config)
    await issuance_lease.ping()
    authority = claim.RedisAuthority(issuance_lease)
    service = getattr(proxy_server.app.state, "kubetee_gamma_private_management", None)
    if service is None:
        raise RuntimeError("native private management identity missing at claim bridge setup")
    service.issuance_lease = issuance_lease
    bridge = claim.PrivateWorkerResponse(worker_http, native_delivery)
    # KubeTEEGammaClaimHandler closes the transport and RedisAuthority.cache.
    handler = claim.KubeTEEGammaClaimHandler(bridge, authority=authority,
        wait_seconds=float(os.environ.get("KUBETEE_GAMMA_WAIT_SECONDS", str(claim.DEFAULT_WAIT_SECONDS))))
    handler.register(proxy_server.app)


async def initialize_private_management(fetch, client_class=None):
    """Post-Prisma hook: no public route, Redis bridge, or worker socket here.

    ``fetch`` is injected by the measured bootstrap after native east-west
    custody succeeds. The process entrypoint stays independent of Prisma;
    this hook runs only after LiteLLM's native DB lifecycle has completed.
    """
    if os.environ.get("KUBETEE_GAMMA_ENABLED", "").lower() not in {"true", "1"}:
        return None
    if client_class is None:
        import httpx
        client_class = httpx.AsyncClient
    from pathlib import Path
    import kubetee_eastwest
    root = Path(os.environ.get("KUBETEE_EASTWEST_DIR", "/run/kubetee-eastwest"))
    resources = {
        "gamma-gateway-client.crt": "default/gamma-gateway-client/tls.crt",
        "gamma-gateway-client.key": "default/gamma-gateway-client/tls.key",
        "gamma-gateway-private.pem": "default/gamma-gateway-private/tls.crt",
        "gamma-gateway-private.key": "default/gamma-gateway-private/tls.key",
        # Public worker server DER, no worker private key enters this guest.
        "gamma-worker-server.crt": os.environ.setdefault(
            "KUBETEE_GAMMA_KBS_WORKER_SERVER_CERT", "default/gamma-worker-server/tls.crt"),
    }
    async with client_class(timeout=30) as client:
        for name, remote in resources.items():
            path = root / name
            path.write_bytes(await fetch(client, remote))
            path.chmod(0o600)
    with (root / "gamma-gateway-client.crt").open("rb") as stream:
        client_crt = stream.read()
    with (root / "gamma-gateway-client.key").open("rb") as stream:
        client_key = stream.read()
    (root / "gamma-gateway-client.pem").write_bytes(client_crt + client_key)
    (root / "gamma-gateway-client.pem").chmod(0o600)
    os.environ.update({
        "KUBETEE_GAMMA_MTLS_CA": str(root / "ca.pem"),
        "KUBETEE_GAMMA_MTLS_CERT": str(root / "gamma-gateway-private.pem"),
        "KUBETEE_GAMMA_MTLS_KEY": str(root / "gamma-gateway-private.key"),
        "KUBETEE_GAMMA_MTLS_BOOTSTRAP_READY": "gateway-leaf-pin-ok",
        "KUBETEE_GAMMA_MTLS_CLIENT_CERT": str(root / "gamma-gateway-client.pem"),
        "KUBETEE_GAMMA_MTLS_CLIENT_KEY": str(root / "gamma-gateway-client.key"),
    })
    for name, variable in (("gamma-gateway-client.crt", "KUBETEE_GAMMA_CLIENT_CERT_SHA256"),
                           ("gamma-gateway-private.pem", "KUBETEE_GAMMA_MTLS_CERT_SHA256")):
        with (root / name).open("rb") as stream:
            digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(stream.read())).hexdigest()
        if digest != os.environ.get(variable):
            raise RuntimeError(f"KBS {name} does not match its release fingerprint")
    thread = start_private_listener()
    if thread is None:
        raise RuntimeError("explicit private Gamma initialization did not bind mTLS")
    service = getattr(thread, "_gamma_service", None)
    if not isinstance(service, kubetee_gamma_management.GammaManagement):
        raise RuntimeError("private native service identity was not established")
    server = thread._gamma_server
    for attempt in range(120):
        if not thread.is_alive() or server.should_exit:
            raise RuntimeError("private Gamma mTLS listener failed during startup")
        if server.started:
            break
        await asyncio.sleep(0.25)
    else:
        raise RuntimeError("private Gamma mTLS listener did not become ready in 30 seconds")
    service.issuance_lease = None
    os.environ["KUBETEE_GAMMA_PRIVATE_MANAGEMENT_READY"] = "1"
    return thread
