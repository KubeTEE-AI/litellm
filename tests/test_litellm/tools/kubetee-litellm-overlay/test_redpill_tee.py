"""Trust boundary shared by all models on RedPill's TEE-only endpoint."""
from __future__ import annotations

import asyncio
import importlib
import importlib.util
import json
import ssl
import sys
from pathlib import Path
from unittest.mock import Mock

import certifi
import httpx
import openai
import pytest

SPEC = importlib.util.spec_from_file_location(
    "redpill_tee",
    Path(__file__).resolve().parents[4] / "tools/kubetee-litellm-overlay/redpill_tee.py",
)
assert SPEC and SPEC.loader
redpill_tee = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = redpill_tee
SPEC.loader.exec_module(redpill_tee)


def context(client: openai.OpenAI | openai.AsyncOpenAI) -> ssl.SSLContext:
    return client._client._transport._pool._ssl_context


def params():
    return {"model_info": {
        "id": "db-id", "tags": ["origin=redpill", "tee"],
        "allow_fail_open": False, "access_groups": ["origin-redpill-models"],
        "upstream_tracking": "receipt-forwarded-unverified",
    }}


def redpill_deployment_model_info(**overrides):
    return {**params()["model_info"], **overrides}


def redpill_deployment_values(**overrides):
    return {
        "model": "openai/qwen/qwen3.8-27b",
        "api_base": redpill_tee.TEE_API_BASE,
        "api_key": "os.environ/REDPILL_API_KEY",
        "num_retries": 0, **params(), **overrides,
    }


def redpill_deployment(**overrides):
    from litellm.types.router import Deployment
    return Deployment(model_name="qwen/qwen3.8-27b",
        litellm_params=redpill_deployment_values(**overrides),
        model_info=overrides.pop("model_info", None) or params()["model_info"],
    )


def close(client):
    if isinstance(client, openai.AsyncOpenAI):
        asyncio.run(client.close())
    else:
        client.close()


@pytest.fixture
def encrypt(monkeypatch):
    module = importlib.import_module("litellm.proxy.common_utils.encrypt_decrypt_utils")
    monkeypatch.setattr(module, "get_salt_key", lambda: "unit-key")
    monkeypatch.setattr(module, "_get_encryption_algorithm", lambda: "aes-256-gcm")
    return module


def test_qwen_client_has_certifi_web_pki_without_eastwest_mtls():
    client = redpill_tee.build_redpill_tee_client(
        is_async=True, api_base=redpill_tee.TEE_API_BASE,
        model="qwen/qwen3.8-27b", api_key="unit-key", litellm_params=params(),
    )
    assert type(client._client._transport).__name__ == "AsyncHTTPTransport"
    tls = context(client)
    assert tls.check_hostname and tls.verify_mode == ssl.CERT_REQUIRED
    expected = ssl.create_default_context(cafile=certifi.where())
    assert tls.cert_store_stats()["x509_ca"] == expected.cert_store_stats()["x509_ca"]
    assert not tls.cert_store_stats().get("x509_client", 0)
    assert client.api_key == "unit-key"
    close(client)


@pytest.mark.parametrize("model_name", ["qwen/qwen3.8-27b", "z-ai/glm-5.3", "future/tee-2"])
def test_endpoint_supports_future_tee_models_without_name_switch(model_name):
    assert redpill_tee.resolve_redpill_api_base(params(), redpill_tee.TEE_API_BASE, model=model_name)


@pytest.mark.parametrize("url", [
    "https://api.redpill.ai/v1", "https://redpill.ai/v1",
    "https://tee.redpill.ai.evil.example/v1", "https://tee.redpill.ai@evil.example/v1",
    "https://tee.redpill.ai:444/v1", "http://tee.redpill.ai/v1",
    "https://tee.redpill.ai/v1?next=internal", "https://tee.redpill.ai/v1#next=internal",
    "https://tee.redpill.ai:bad/v1", "https://tee.redpill.ai//v1", "https://tee.redpill.ai/",
])
def test_no_unverified_tee_fallback(url):
    with pytest.raises(ValueError, match="TEE-only"):
        redpill_tee.resolve_redpill_api_base(params(), url)


@pytest.mark.parametrize("url", [redpill_tee.TEE_API_BASE, redpill_tee.TEE_API_BASE + "/", "https://tee.redpill.ai:443/v1"])
def test_endpoint_accepts_only_safe_equivalent_url(url):
    assert redpill_tee.resolve_redpill_api_base(params(), url) == url


def test_real_adapter_builds_isolated_client_only_for_valid_tags():
    redpill_tee.apply_redpill_tee_trust()
    from litellm.llms.openai.openai import OpenAIChatCompletion
    provider = OpenAIChatCompletion()
    client = provider._get_openai_client(
        is_async=True, api_base=redpill_tee.TEE_API_BASE,
        litellm_params=params(), api_key="unit-key", model="qwen/qwen3.8-27b",
    )
    assert type(client._client._transport).__name__ == "AsyncHTTPTransport"
    assert not client._client._transport._pool._ssl_context.cert_store_stats().get("x509_client", 0)
    close(client)
    for litellm_params in (None, {}, {"litellm_metadata": {"model_info": {"tags": ["default"]}}}):
        with pytest.raises(ValueError, match="TEE-only"):
            provider._get_openai_client(
                is_async=True, api_base=redpill_tee.TEE_API_BASE,
                litellm_params=litellm_params, api_key="unit-key", model="qwen/qwen3.8-27b",
            )


def test_async_and_sync_transport_methods_use_independent_clients():
    clients = [redpill_tee.build_redpill_tee_client(
        is_async=is_async, api_base="https://tee.redpill.ai:443/v1/",
        api_key="unit-key", litellm_params=params(),
    ) for is_async in (True, False)]
    assert type(clients[0]._client._transport).__name__ == "AsyncHTTPTransport"
    assert type(clients[1]._client._transport).__name__ == "HTTPTransport"
    for client in clients:
        assert client._base_url.host == "tee.redpill.ai"
        assert client._base_url.path == "/v1/"
        assert client._base_url.port in (None, 443) if hasattr(client._base_url, "port") else True
        close(client)


@pytest.mark.parametrize("changes", [
    {"model_info": redpill_deployment_model_info(tags=["origin=redpill"])},
        {"model": "openai/"},
        {"model": "kimi-k3/qwen3.8-27b"},
    {"api_key": "leaked-literal"}, {"api_key": "resolved-secret"},
    {"num_retries": 3}, {"num_retries": None},
    {"model_info": redpill_deployment_model_info(access_groups=[])},
    {"model_info": redpill_deployment_model_info(allow_fail_open=True)},
    {"model_info": redpill_deployment_model_info(tags=["origin=redpill", "tee", "default"])},
    {"fallbacks": ["internal-model"]}, {"context_window_fallbacks": ["internal-model"]},
    {"content_policy_fallbacks": ["internal-model"]},
    {"model_info": redpill_deployment_model_info(upstream_tracking="verified")},
])
def test_registration_rejects_insecure_deployment_metadata(changes):
    with pytest.raises(ValueError, match="TEE-only"):
        redpill_tee.validate_redpill_deployment(redpill_deployment_values(**changes))


def test_registration_accepts_explicit_tee_admin_metadata():
    for model in ["qwen/qwen3.8-27b", "future/model-with-any-name"]:
        redpill_tee.validate_redpill_deployment(redpill_deployment_values(model="openai/" + model))
    redpill_tee.validate_redpill_deployment({"model": "openai/local", "api_base": "https://internal/v1"})


def test_router_upsert_uses_real_deployment_metadata(monkeypatch):
    from litellm.router import Router
    redpill_tee.apply_redpill_tee_trust()
    monkeypatch.setenv("REDPILL_API_KEY", "resolved-secret")
    router = Router(model_list=[])
    assert router.upsert_deployment(redpill_deployment(api_key="resolved-secret")) is not None
    assert router.model_list[0]["model_name"] == "qwen/qwen3.8-27b"
    assert dict(router.model_list[0]["model_info"])["tags"] == ["origin=redpill", "tee"]


def test_router_upsert_rejects_non_tee_row_before_replacing_live_row():
    from litellm.router import Router
    redpill_tee.apply_redpill_tee_trust()
    router = Router(model_list=[])
    router.upsert_deployment(redpill_deployment())
    with pytest.raises(ValueError, match="TEE-only"):
        router.upsert_deployment(redpill_deployment(api_base="https://api.redpill.ai/v1"))
    assert len(router.model_list) == 1
    assert router.model_list[0]["litellm_params"]["api_base"] == redpill_tee.TEE_API_BASE


def test_proxy_config_guard_applies_to_future_tee_models():
    redpill_tee.apply_redpill_tee_trust()
    for model in ["qwen/qwen3.8-27b", "future-vendor/future-model", "another-future-vendor/model"]:
        redpill_tee.validate_redpill_config({"model_list": [{
            "model_name": model,
            "litellm_params": redpill_deployment_values(model="openai/" + model),
        }]})


@pytest.mark.asyncio
async def test_admin_api_create_rejects_resolved_secret_before_persistence():
    from litellm.proxy.management_endpoints.model_management_endpoints import add_model_to_db
    runtime = Mock()
    runtime.litellm_proxy_model_table.create = Mock()
    with pytest.raises(ValueError, match="TEE-only"):
        await add_model_to_db(redpill_deployment(api_key="resolved-secret"), Mock(user_id="admin"), runtime)
    runtime.litellm_proxy_model_table.create.assert_not_called()


@pytest.mark.parametrize("params_change, applied_info", [
    ({"api_key": "resolved-secret"}, None),
    ({"api_key": "v2:gcm:encrypted-ciphertext"}, None),
    ({"api_base": "https://api.redpill.ai/v1"}, None),
    ({}, {"allow_fail_open": True}), ({}, {"access_groups": []}),
    ({"model": "not-openai/qwen3.8-27b"}, None),
])
def test_patch_uses_effective_merged_row_before_encryption(params_change, applied_info):
    from litellm.proxy.management_endpoints.model_management_endpoints import update_db_model
    from litellm.types.router import updateDeployment
    patch = updateDeployment.model_validate({"litellm_params": params_change, "model_info": applied_info or {}})
    with pytest.raises(ValueError, match="TEE-only"):
        update_db_model(redpill_deployment(), patch)


@pytest.mark.parametrize("params_change, applied_info", [
    ({}, {"description": "Updated label"}),
    ({"model": "openai/qwen/qwen3.8-27b", "api_base": redpill_tee.TEE_API_BASE,
      "api_key": "os.environ/REDPILL_API_KEY", "num_retries": 0}, {}),
])
def test_patch_preserving_policy_stays_valid(params_change, applied_info, encrypt):
    from litellm.proxy.management_endpoints.model_management_endpoints import update_db_model
    from litellm.types.router import updateDeployment
    patch = updateDeployment.model_validate({"litellm_params": params_change, "model_info": applied_info or {}})
    assert update_db_model(redpill_deployment(), patch)["model_name"] == "qwen/qwen3.8-27b"


def test_put_encrypts_pointer_not_secret(encrypt):
    from litellm.proxy.management_endpoints import model_management_endpoints as endpoint
    from litellm.types.router import updateDeployment
    result = endpoint.update_db_model(redpill_deployment(), updateDeployment(
        model_info={"description": "Put round trip"}, litellm_params=redpill_deployment_values(),
    ))
    params_result = json.loads(result["litellm_params"])
    assert encrypt.decrypt_value_helper(params_result["api_key"], "api_key") == "os.environ/REDPILL_API_KEY"
    assert encrypt.decrypt_value_helper(params_result["model"], "model") == "openai/qwen/qwen3.8-27b"


def test_second_put_accepts_decrypted_pointer_from_stored_row(encrypt):
    from litellm.proxy.management_endpoints import model_management_endpoints as endpoint
    from litellm.types.router import GenericLiteLLMParams, updateDeployment
    model = encrypt.encrypt_value_helper("openai/qwen/qwen3.8-27b")
    existing = redpill_deployment()
    object.__setattr__(existing, "model_name", "qwen/qwen3.8-27b")
    object.__setattr__(existing, "litellm_params", GenericLiteLLMParams.model_validate(
        redpill_deployment_values(model=model),
    ))
    encrypted = encrypt.encrypt_value_helper("os.environ/REDPILL_API_KEY")
    result = endpoint.update_db_model(existing, updateDeployment(
        model_info={"description": "Second put"}, litellm_params={"api_key": encrypted},
    ))
    stored_key = json.loads(result["litellm_params"])["api_key"]
    assert encrypt.decrypt_value_helper(stored_key, "api_key") == "os.environ/REDPILL_API_KEY"


@pytest.mark.asyncio
async def test_router_qwen_request_uses_public_name_and_web_pki(monkeypatch):
    import httpx

    from litellm.router import Router
    redpill_tee.apply_redpill_tee_trust()
    router = Router(model_list=[], enable_pre_call_checks=True)
    router.upsert_deployment(redpill_deployment())
    from litellm.llms.openai.openai import OpenAIChatCompletion
    monkeypatch.setenv("REDPILL_API_KEY", "resolved-secret")
    captured = []
    seen_clients = []

    async def handler(request):
        captured.append(request)
        return httpx.Response(200, headers={"x-receipt-id": "unit-receipt"}, json={
            "id": "chatcmpl-unit", "object": "chat.completion", "created": 1,
            "model": "qwen/qwen3.8-27b",
            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "OK"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        })

    original_build = redpill_tee.build_redpill_tee_client
    def verify_before_request(**kwargs):
        if not seen_clients:
            seen_clients.append(type(httpx.AsyncHTTPTransport()._pool._ssl_context))
        client = original_build(**kwargs)
        transport = httpx.MockTransport(handler)
        client._client = httpx.AsyncClient(transport=transport, base_url=redpill_tee.TEE_API_BASE)
        return client

    assert OpenAIChatCompletion._get_openai_client._redpill_guard
    monkeypatch.setattr(redpill_tee, "build_redpill_tee_client", verify_before_request)
    response = await router.acompletion(model="qwen/qwen3.8-27b", messages=[{"role": "user", "content": "Reply OK"}], num_retries=0)
    assert response.choices[0].message.content == "OK"
    assert len(captured) == 1
    request = captured[0]
    assert request.url == httpx.URL(redpill_tee.TEE_API_BASE + "/chat/completions")
    assert json.loads(request.content)["model"] == "qwen/qwen3.8-27b"
    assert not captured[0].headers.get("kubetee-client-cert")
    assert seen_clients and seen_clients[0] is not None


@pytest.mark.asyncio
async def test_router_preserves_native_qwen_streaming(monkeypatch):
    from litellm.router import Router
    redpill_tee.apply_redpill_tee_trust()
    monkeypatch.setenv("REDPILL_API_KEY", "resolved-secret")
    router = Router(model_list=[], enable_pre_call_checks=True)
    router.upsert_deployment(redpill_deployment(api_key="resolved-secret"))

    async def handler(request):
        assert json.loads(request.content)["model"] == "qwen/qwen3.8-27b"
        assert "SSLKEYLOGFILE" not in request.headers
        return httpx.Response(200, text=(
            'data: {"id":"s","object":"chat.completion.chunk","created":1,'
            '"model":"qwen/qwen3.8-27b","choices":[{"index":0,"delta":{"role":"assistant","content":"TEE"}}]}\n\ndata: [DONE]\n\n'
        ))

    original_build = redpill_tee.build_redpill_tee_client
    def transport_factory(**kwargs):
        client = original_build(**kwargs)
        client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        return client
    monkeypatch.setattr(redpill_tee, "build_redpill_tee_client", transport_factory)
    stream = await router.acompletion(model="qwen/qwen3.8-27b", messages=[{"role": "user", "content": "Stream"}], stream=True, num_retries=0)
    contents = []
    async for chunk in stream:
        contents.append(chunk.choices[0].delta.content)
    assert "TEE" in contents


def test_non_redpill_client_is_not_replaced(monkeypatch):
    from litellm.llms.openai.openai import OpenAIChatCompletion
    cached = Mock()
    monkeypatch.setattr(OpenAIChatCompletion, "get_cached_openai_client", cached)
    cached.return_value = openai.AsyncOpenAI(api_key="unit-key", base_url="http://unit/v1")
    redpill_tee.apply_redpill_tee_trust()
    result = OpenAIChatCompletion()._get_openai_client(
        is_async=True, api_base="http://kimi-k3-sglang.nemo.svc:8000/v1",
        api_key="dummy",
    )
    assert result is cached.return_value
    cached.assert_called_once()


def test_dotted_callback_loader_instantiates_redpill_policy():
    from litellm.proxy.types_utils.utils import get_instance_fn
    assert get_instance_fn("redpill_tee.redpill_tee_logger") is redpill_tee.redpill_tee_logger
