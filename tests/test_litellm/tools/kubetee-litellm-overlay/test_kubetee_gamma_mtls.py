"""Verified TLS-worker boundary for the private Gamma native callback socket."""
import asyncio
import base64
import concurrent.futures
import contextlib
import hashlib
import json
from decimal import Decimal
import socket
import os
import ssl
from pathlib import Path
from types import SimpleNamespace
import sys
from datetime import datetime, timezone

import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from httpx import AsyncClient, ASGITransport

import kubetee_gamma_management as mg
import kubetee_gamma_private_mtls as private
from test_kubetee_gamma_management import (HK, COLD, SECRET, SyntheticStore, fresh_checkpoint,
                                          settlement_intent, settled_checkpoint)


@pytest.mark.asyncio
async def test_gateway_private_callback_uses_only_verified_socket(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "litellm-gateway-mtls.litellm.svc.cluster.local")])
    from datetime import datetime, timedelta, timezone
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("litellm-gateway-mtls.litellm.svc.cluster.local")]), critical=False)
        .sign(key, hashes.SHA256()))
    der = certificate.public_bytes(serialization.Encoding.DER)
    fingerprint = hashlib.sha256(der).hexdigest()
    (tmp_path/"gateway.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    (tmp_path/"worker.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    (tmp_path/"worker.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    import sys
    sys.path.insert(0, str(Path(os.environ["KUBETEE_GAMMA_WORKER_ROOT"]) / "tests"))
    from certificates import issue_certificates
    leaves = issue_certificates(tmp_path, fourth_client=True)
    assert len({entry[0] for entry in leaves.values()}) == 4
    client_pem = tmp_path / "worker-client.crt"
    client_key = tmp_path / "worker-client.key"
    store = SyntheticStore()
    service = mg.GammaManagement(proxy=store, certificate_fingerprint=leaves["worker-client"][0], proxy_ip="127.0.0.1",
                                 models=["z-ai/glm-5.3"])
    app = private.create_private_application(service)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(20)
    configuration = uvicorn.Config(app, http=private.PrivateTransportProtocol,
        ssl_certfile=str(tmp_path/"gateway-server.crt"), ssl_keyfile=str(tmp_path/"gateway-server.key"),
        ssl_ca_certs=str(tmp_path/"ca.crt"), ssl_cert_reqs=ssl.CERT_REQUIRED,
        log_level="error", timeout_keep_alive=1)
    server = uvicorn.Server(configuration)
    server.capture_signals = lambda: contextlib.nullcontext()
    task = asyncio.create_task(server.serve(sockets=[listener]))
    await asyncio.sleep(.15)
    context = ssl.create_default_context(cafile=str(tmp_path/"ca.crt"))
    context.load_cert_chain(str(client_pem), str(client_key))
    wrong_leaf_context = ssl.create_default_context(cafile=str(tmp_path/"gateway-server.crt"))
    wrong_leaf_context.load_cert_chain(str(tmp_path/"worker-server.crt"), str(tmp_path/"worker-server.key"))
    async def request(path, body, spoof=False, client_context=None):
        reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", listener.getsockname()[1],
                                      ssl=client_context or context, server_hostname="litellm-gateway-mtls.litellm.svc.cluster.local"), 5)
        data = json.dumps(body).encode()
        forged = b"X-Kubetee-Worker-Cert-DER: YmFk\r\nX-Kubetee-Worker-Proof: YmFk\r\n" if spoof else b""
        writer.write(b"POST "+path.encode()+b" HTTP/1.1\r\nHost: gateway\r\nContent-Type: application/json\r\nContent-Length: "+str(len(data)).encode()+b"\r\nConnection: close\r\n"+forged+b"\r\n"+data)
        await writer.drain()
        result = await asyncio.wait_for(reader.read(), 5)
        writer.close()
        await writer.wait_closed()
        return result
    try:
        result = await request("/internal/v1/gamma/key/reservation",
             {"hotkey_ss58": HK, "network": "finney", "genesis_hash": mg.GENESIS, "netuid": 90,
              "checkpoint": fresh_checkpoint(), "key_alias": fresh_checkpoint()["observation_coldkey"] + "-" + HK.lower(),
              "target_permissions": {"models": ["z-ai/glm-5.3"], "mcp_servers": None}}, spoof=True)
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", listener.getsockname()[1], ssl=context,
            server_hostname="litellm-gateway-mtls.litellm.svc.cluster.local")
        writer.write(b"GET /internal/v1/ready HTTP/1.1\r\nHost: gateway\r\nConnection: close\r\n\r\n")
        await writer.drain()
        response = await asyncio.wait_for(reader.read(), 5)
        writer.close()
        await writer.wait_closed()
        assert response.startswith(b"HTTP/1.1 200 OK"), response
        assert json.loads(response.split(b"\r\n\r\n", 1)[1]) == {"ready": True}
        # The third leaf is serverAuth ONLY: a peer using it as a client must
        # never prove the worker's fourth-leaf outbound mTLS identity.
        service.fingerprint = leaves["worker-server"][0]
        rejected = await request("/internal/v1/gamma/key/reservation", {})
        assert rejected.startswith(b"HTTP/1.1 403 Forbidden"), rejected
        # A valid CA-issued serverAuth leaf still fails the fourth-leaf inbound pin.
        wrong_role_response = await request("/internal/v1/gamma/key/reservation", {}, client_context=wrong_leaf_context)
        assert wrong_role_response[:12] in (b"", b"HTTP/1.1 403"), repr(wrong_role_response)
        service.fingerprint = leaves["worker-client"][0]
        assert store.row.key_alias == fresh_checkpoint()["observation_coldkey"] + "-" + HK.lower()
        assert store.row.max_budget == "0"
        assert store.row.blocked is True
        metadata = json.loads(store.row.metadata)
        assert metadata["gamma_hotkey"] == HK
        assert store.row.key_alias == metadata["gamma"]["observation_coldkey"] + "-" + HK.lower()
        assert not metadata["gamma"]["total_settled_units"]
        # set of zero-budget blocked row is intentional; no caller can supply
        # money or credit in ReservationRequest. Credit has its own CAS tests.
        assert store.row.max_budget == "0"
        service.fingerprint = "0" * 64
        result = await request("/internal/v1/gamma/key/issue", {"hotkey_ss58": HK, "network": "finney", "genesis_hash": mg.GENESIS,
            "netuid": "90", "action": "claim", "verification_digest": "0" * 64}, spoof=True)
        assert result.startswith(b"HTTP/1.1 404 Not Found"), result
        assert store.row.max_budget == "0"
        result = await request("/key/generate", {"hotkey_ss58": HK})
        assert result.startswith(b"HTTP/1.1 403 Forbidden"), result
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 5)
        listener.close()


@pytest.mark.asyncio
async def test_loop_owned_native_private_mtls_lifecycle(tmp_path, monkeypatch):
    """TLS callbacks never hand Prisma to the private listener's loop."""
    owner_loop = asyncio.get_running_loop()
    from certificates import issue_certificates
    leaves = issue_certificates(tmp_path, fourth_client=True)
    store = SyntheticStore()
    await store.reserve(HK, fresh_checkpoint(), {"models": ["z-ai/glm-5.3"], "mcp_servers": None}, SECRET)
    settings = {
        "KUBETEE_GAMMA_ENABLED": "true",
        "KUBETEE_GAMMA_MTLS_BOOTSTRAP_READY": "gateway-leaf-pin-ok",
        "KUBETEE_GAMMA_MTLS_CA": str(tmp_path / "ca.crt"),
        "KUBETEE_GAMMA_MTLS_CERT": str(tmp_path / "gateway-server.crt"),
        "KUBETEE_GAMMA_MTLS_KEY": str(tmp_path / "gateway-server.key"),
        "KUBETEE_GAMMA_MTLS_CERT_SHA256": leaves["gateway-server"][0],
        "KUBETEE_GAMMA_WORKER_CLIENT_CERT_SHA256": leaves["worker-client"][0],
        "KUBETEE_GAMMA_MODELS": "z-ai/glm-5.3",
        "KUBETEE_GAMMA_MTLS_PORT": "0",
    }
    public_app = SimpleNamespace(state=SimpleNamespace())
    proxy_server = SimpleNamespace(app=public_app)
    proxy_module = SimpleNamespace(proxy_server=proxy_server)
    monkeypatch.setitem(sys.modules, "litellm.proxy", proxy_module)
    monkeypatch.setitem(sys.modules, "litellm.proxy.proxy_server", proxy_server)
    mock_proxy = SimpleNamespace(app=SimpleNamespace(
        state=SimpleNamespace(kubetee_gamma_handler=None)))
    mock_proxy_module = SimpleNamespace(proxy_server=mock_proxy)
    thread = private.create_private_listener(settings)
    service = thread._gamma_service
    service.proxy = store
    async def enforced_key(hotkey):
        assert asyncio.get_running_loop() is owner_loop
        return await mg.GammaManagement.key(service, hotkey)
    service.key = enforced_key
    thread._gamma_service.owner_loop = owner_loop
    thread.start()
    try:
        for _ in range(100):
            if thread._gamma_server.started:
                break
            assert thread.is_alive()
            await asyncio.sleep(.01)
        assert thread._gamma_server.started
        application = thread._gamma_server.config.app
        assert isinstance(application, private.NativeLoopDispatcher)
        assert application.service.owner_loop is owner_loop
        port = thread._gamma_listener.getsockname()[1]
        context = ssl.create_default_context(cafile=str(tmp_path / "ca.crt"))
        context.load_cert_chain(str(tmp_path / "worker-client.crt"),
                                str(tmp_path / "worker-client.key"))
        reader, writer = await asyncio.wait_for(asyncio.open_connection(
            "127.0.0.1", port, ssl=context,
            server_hostname="litellm-gateway-mtls.litellm.svc.cluster.local"), 5)
        query = f"hotkey_ss58={HK}&network=finney&genesis_hash={mg.GENESIS}&netuid=90"
        writer.write(f"GET /internal/v1/gamma/key?{query} HTTP/1.1\r\n"
                     "Host: litellm-gateway-mtls.litellm.svc.cluster.local:8443\r\n"
                     "Connection: close\r\n\r\n".encode())
        await writer.drain()
        response = await asyncio.wait_for(reader.read(), 5)
        writer.close()
        await writer.wait_closed()
        assert response.startswith(b"HTTP/1.1 200 OK"), response
        assert json.loads(response.split(b"\r\n\r\n", 1)[1])["row"]["key_alias"] == COLD + "-" + HK.lower()
    finally:
        thread._gamma_server.should_exit = True
        await asyncio.get_running_loop().run_in_executor(None, thread.join, 5)
        thread._gamma_listener.close()
        assert not thread.is_alive()


@pytest.mark.asyncio
async def test_claim_bridge_defaults_fit_public_bounded_wait(monkeypatch):
    import kubetee_gamma_claim as claim
    monkeypatch.setenv("KUBETEE_GAMMA_PRIVATE_MANAGEMENT_READY", "1")
    monkeypatch.setenv("KUBETEE_GAMMA_MTLS_CA", "/unused")
    monkeypatch.delenv("KUBETEE_GAMMA_WAIT_SECONDS", raising=False)
    import inspect
    assert float(claim.DEFAULT_WAIT_SECONDS) <= claim.MAX_WAIT_SECONDS
    source = inspect.getsource(private.connect_public_claims)
    assert 'str(claim.DEFAULT_WAIT_SECONDS)' in source


@pytest.mark.asyncio
async def test_management_routes_cannot_attach_to_public_application():
    from fastapi import FastAPI
    store = SyntheticStore()
    with pytest.raises(RuntimeError, match="dedicated private"):
        mg.installed_router(FastAPI(), mg.GammaManagement(proxy=store,
            certificate_fingerprint="ab" * 32, proxy_ip="127.0.0.1", models=["z-ai/glm-5.3"]))


def test_native_sentinel_monitor_credentials_remain_distinct(monkeypatch):
    from unittest.mock import MagicMock, patch
    from kubetee_gamma_transport import native_async_redis, redis_production_settings

    config = redis_production_settings(
        "rediss+sentinel://data-user:data-secret@gamma-sentinel:26379/"
        "?service_name=mymaster&db=12&sentinel_username=monitor-user&sentinel_password=monitor-secret")
    pool = MagicMock()
    constructed = MagicMock()
    discovered = MagicMock()
    discovered.master_for.return_value.connection_pool = pool
    async_client = MagicMock()
    with (patch("litellm._redis.get_redis_async_client", return_value=async_client) as factory,
          patch("redis.asyncio.Sentinel", return_value=discovered) as constructor):
        assert native_async_redis(config) is async_client
        assert discovered.master_for.call_args.args[0] == "mymaster"
        assert discovered.master_for.call_args.kwargs["username"] == "data-user"
        assert discovered.master_for.call_args.kwargs["db"] == 12
        assert discovered.master_for.call_args.kwargs["password"] == "data-secret"
        assert constructor.call_args.args[0] == [["gamma-sentinel", 26379]]
        assert constructor.call_args.kwargs["sentinel_kwargs"] == {
            "username": "monitor-user", "password": "monitor-secret", "ssl": True,
        }
        factory.assert_called_once_with(connection_pool=pool, host="gamma-sentinel")
    config["ssl"] = False
    with pytest.raises(ValueError, match="equal TLS mode"):
        native_async_redis(config)


@pytest.mark.asyncio
async def test_public_lifecycle_pin_redis_and_lease_cleanup(tmp_path, monkeypatch):
    import httpx
    import kubetee_gamma_claim as claim
    import kubetee_gamma_tls as tls
    from certificates import issue_certificates
    leaves = issue_certificates(tmp_path, fourth_client=True)
    (tmp_path / "ca.pem").write_bytes((tmp_path / "ca.crt").read_bytes())
    public_app = SimpleNamespace(state=SimpleNamespace(
        kubetee_gamma_private_management=mg.GammaManagement(
            proxy=SyntheticStore(),
            certificate_fingerprint=leaves["worker-client"][0],
            proxy_ip="127.0.0.1", models=["z-ai/glm-5.3"])))
    proxy_server = SimpleNamespace(app=public_app)
    monkeypatch.setitem(sys.modules, "litellm.proxy", SimpleNamespace(proxy_server=proxy_server))
    monkeypatch.setitem(sys.modules, "litellm.proxy.proxy_server", proxy_server)
    for name, value in {
        "KUBETEE_GAMMA_PRIVATE_MANAGEMENT_READY": "1",
        "KUBETEE_GAMMA_MTLS_CA": str(tmp_path / "ca.crt"),
        "KUBETEE_GAMMA_MTLS_CLIENT_CERT": str(tmp_path / "gateway-client.crt"),
        "KUBETEE_GAMMA_MTLS_CLIENT_KEY": str(tmp_path / "gateway-client.key"),
        "KUBETEE_GAMMA_WORKER_URL": "https://gamma-funder.kubetee-ops.svc.cluster.local:8443",
        "KUBETEE_GAMMA_WORKER_CERT_SHA256": leaves["worker-server"][0],
        "KUBETEE_GAMMA_REDIS_URL": "redis://synthetic:6379/12",
    }.items():
        monkeypatch.setenv(name, value)
    records = []
    clients = []
    real_client = httpx.AsyncClient
    class RecordingClient:
        def __init__(self, **kwargs):
            records.append(kwargs)
            clients.append(real_client(**kwargs))
    class Redis:
        def __init__(self):
            self.closed = False
        def register_script(self, script):
            return None
        async def ping(self):
            return True
        async def aclose(self):
            self.closed = True
    redis = Redis()
    registered = []
    monkeypatch.setattr(private.httpx, "AsyncClient", RecordingClient)
    monkeypatch.setattr("kubetee_gamma_transport.native_async_redis", lambda config: redis)
    monkeypatch.setattr(claim.KubeTEEGammaClaimHandler, "register", lambda self, app: registered.append(app))
    await private.connect_public_claims()
    transport = records[0]["transport"]
    assert isinstance(transport, tls.PinningAsyncTransport)
    assert transport.extensions == {"sni_hostname": "gamma-funder.kubetee-ops.svc.cluster.local"}
    assert transport.fingerprint == leaves["worker-server"][0]
    assert leaves["gateway-client"][0] != leaves["worker-server"][0]
    assert public_app.state.kubetee_gamma_private_management.issuance_lease is redis
    assert registered == [public_app]
    authority = claim.RedisAuthority(redis)
    handler = claim.KubeTEEGammaClaimHandler(
        claim.PrivateWorkerResponse(
            clients[0],
            private.InProcessIssueClient(public_app.state.kubetee_gamma_private_management),
        ),
        authority=authority,
    )
    await handler.close()
    assert redis.closed is True
    assert clients[0].is_closed


def test_private_configuration_is_disabled_and_fail_closed(tmp_path):
    assert private.create_private_listener({}) is None
    with pytest.raises(RuntimeError, match="fingerprint"):
        private.create_private_listener({"KUBETEE_GAMMA_ENABLED": "1"})


@pytest.mark.asyncio
async def test_bootstrap_wraps_bound_prisma_lifecycle_and_public_claims(monkeypatch):
    from contextlib import asynccontextmanager
    from types import SimpleNamespace
    import sys
    calls = []
    @asynccontextmanager
    async def bound_prisma(app):
        calls.append("prisma")
        yield {"database": "ready"}
    original_proxy = contextlib.asynccontextmanager(lambda app: pytest.fail("hook changed"))
    class Bridge:
        async def close(self):
            calls.append("close")
    public = SimpleNamespace(router=SimpleNamespace(lifespan_context=bound_prisma),
                            state=SimpleNamespace(kubetee_gamma_handler=Bridge()))
    proxy = SimpleNamespace(app=public, proxy_startup_event=original_proxy)
    async def start_private(fetch):
        assert fetch is synthetic_fetch
        calls.append("private")
    async def connect_public():
        calls.append("public")
    async def synthetic_fetch():
        calls.append("eastwest")
    fake_eastwest = SimpleNamespace(fetch_eastwest=synthetic_fetch, _fetch=synthetic_fetch)
    fake_mtls = SimpleNamespace(initialize_private_management=start_private,
                               connect_public_claims=connect_public)
    monkeypatch.setitem(sys.modules, "kubetee_eastwest", fake_eastwest)
    monkeypatch.setitem(sys.modules, "kubetee_gamma_private_mtls", fake_mtls)
    monkeypatch.setitem(sys.modules, "litellm.proxy", SimpleNamespace(proxy_server=proxy))
    monkeypatch.setitem(sys.modules, "litellm.proxy.proxy_server", proxy)
    monkeypatch.setenv("KUBETEE_GAMMA_ENABLED", "true")
    import kubetee_bootstrap
    await kubetee_bootstrap.main()
    assert proxy.proxy_startup_event is public.router.lifespan_context
    async with public.router.lifespan_context(public) as state:
        assert state == {"database": "ready"}
    assert calls == ["eastwest", "prisma", "private", "public", "close"]


@pytest.mark.asyncio
async def test_disabled_bootstrap_does_not_import_private_claims(monkeypatch):
    from types import SimpleNamespace
    import sys
    async def synthetic_fetch(): pass
    fake = SimpleNamespace(fetch_eastwest=synthetic_fetch, _fetch=synthetic_fetch)
    monkeypatch.setitem(sys.modules, "kubetee_eastwest", fake)
    monkeypatch.delenv("KUBETEE_GAMMA_ENABLED", raising=False)
    import kubetee_bootstrap
    await kubetee_bootstrap.main()
