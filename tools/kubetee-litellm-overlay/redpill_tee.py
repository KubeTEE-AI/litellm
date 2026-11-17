"""Public Web-PKI transport for tagged models on RedPill's TEE endpoint.

The OpenAI adapter remains LiteLLM's native request/streaming/response path.
Only admin-declared deployment tags replace its HTTP client. The KBS east-west
CA and client certificate remain on all other OpenAI clients.
"""
from __future__ import annotations

import os
import ssl
from collections.abc import Mapping
from typing import Any, Final
from urllib.parse import urlsplit

import certifi
import httpx
import openai

from litellm.integrations.custom_logger import CustomLogger
from litellm.llms.openai.openai import OpenAIChatCompletion

TEE_API_BASE: Final = "https://tee.redpill.ai/v1"
ERROR: Final = (
    "TEE-only RedPill deployments require tags ['origin=redpill', 'tee'], "
    f"HTTPS api_base {TEE_API_BASE}, and os.environ/REDPILL_API_KEY"
)


def deployment_tags(params: object) -> set[str]:
    if not isinstance(params, Mapping):
        return set()
    info = params.get("model_info")
    values = (info.get("tags") if isinstance(info, Mapping) else None) or params.get("tags") or []
    return {tag for tag in values if isinstance(tag, str)}


def effective_params(litellm_params: Any, tags_only: bool = False, **_: Any) -> dict:
    """The router puts model_info in litellm_metadata before request dispatch."""
    values = litellm_params.model_dump(exclude_none=True) if hasattr(litellm_params, "model_dump") else dict(litellm_params or {})
    if not tags_only:
        return values
    metadata = values.get("litellm_metadata") or values.get("metadata") or {}
    info = dict(values.get("model_info") or metadata.get("model_info") or {})
    return {"model_info": info, "model": values.get("model")}


def resolve_redpill_api_base(params: object, api_base: object, **_: object) -> str | None:
    if not {"origin=redpill", "tee"}.issubset(deployment_tags(params)):
        return None
    if not isinstance(api_base, str):
        raise ValueError(ERROR)  # noqa: TRY004 — config validation is a ValueError API boundary
    url = urlsplit(api_base)
    try:
        permitted_port = url.port in (None, 443)
    except ValueError as error:
        raise ValueError(ERROR) from error
    if (
        url.scheme != "https" or url.hostname != "tee.redpill.ai"
        or url.username is not None or url.password is not None
        or not permitted_port or url.path.rstrip("/") != "/v1"
        or url.query or url.fragment
    ):
        raise ValueError(ERROR)
    return api_base


def build_redpill_tee_client(*, is_async: bool, api_base: str, api_key: str | None = None,
                             timeout: Any = 600, max_retries: int = 2,
                             organization: str | None = None,
                             litellm_params: Any = None, **_: Any):
    if resolve_redpill_api_base(litellm_params, api_base) is None:
        raise ValueError(ERROR)
    context = ssl.create_default_context(cafile=certifi.where())
    if is_async:
        transport = httpx.AsyncHTTPTransport(verify=context)
        http = httpx.AsyncClient(transport=transport)
    else:
        http = httpx.Client(transport=httpx.HTTPTransport(verify=context))
    cls = openai.AsyncOpenAI if is_async else openai.OpenAI
    return cls(api_key=api_key or "missing-key", base_url=api_base,
               timeout=timeout, max_retries=max_retries, organization=organization,
               http_client=http)


def validate_redpill_deployment(params: Mapping | Any, model_info: Mapping | Any = None) -> None:
    values = effective_params(params)
    info = dict(values.get("model_info") or {})
    if model_info:
        info.update(effective_params(model_info))
    values["model_info"] = info
    tags = deployment_tags(values)
    url = urlsplit(values.get("api_base") or "") if isinstance(values.get("api_base"), str) else None
    if "origin=redpill" not in tags and (url is None or url.hostname != "tee.redpill.ai"):
        return
    if resolve_redpill_api_base(values, values.get("api_base")) is None:
        raise ValueError(ERROR)
    model = values.get("model")
    if not isinstance(model, str) or not model.startswith("openai/") or not model.removeprefix("openai/").strip("/"):
        raise ValueError(f"{ERROR}; internal provider must be native openai/<any-upstream-model>")
    # The management API persists only os.environ/REDPILL_API_KEY. LiteLLM's
    # Router resolves that same pointer from the validated environment before
    # passing its deployment to get_litellm_params. Do not treat it as raw
    # admin input: after the config/router trust boundary below, the only raw
    # key accepted is the one from that exact environment variable.
    api_key = values.get("api_key")
    credential_source = values.pop("_redpill_credential_source", None)
    environment_key = os.environ.get("REDPILL_API_KEY")
    if not environment_key and credential_source == "runtime":
        raise ValueError(f"{ERROR}; REDPILL_API_KEY must come from pod Secret env")
    if (api_key not in (("os.environ/REDPILL_API_KEY", environment_key)
                        if credential_source == "runtime" else ("os.environ/REDPILL_API_KEY",))
            or "default" in tags):
        raise ValueError(ERROR)
    if values.get("num_retries") != 0:
        raise ValueError(f"{ERROR}; num_retries must be 0: never retry into a non-TEE deployment")
    if list(info.get("access_groups") or []) != ["origin-redpill-models"]:
        raise ValueError(f"{ERROR}; access_groups must be exactly ['origin-redpill-models']")
    if info.get("upstream_tracking") != "receipt-forwarded-unverified":
        raise ValueError(f"{ERROR}; upstream_tracking must be receipt-forwarded-unverified")
    if info.get("allow_fail_open") is not False:
        raise ValueError(f"{ERROR}; allow_fail_open must be false")
    for forbidden in ("allow_fallbacks", "fallbacks", "context_window_fallbacks", "content_policy_fallbacks"):
        if values.get(forbidden):
            raise ValueError(f"{ERROR}; no automatic non-TEE fallback")


def validate_redpill_config(config: Mapping) -> None:
    for deployment in config.get("model_list") or []:
        validate_redpill_deployment(deployment.get("litellm_params") or {}, deployment.get("model_info"))


def apply_redpill_tee_trust() -> bool:
    """Activate from the startup hook, before Router creation/import."""
    from litellm.litellm_core_utils import get_litellm_params
    original_get_params = get_litellm_params.get_litellm_params
    if not getattr(original_get_params, "_redpill_guard", False):
        def guarded_get_params(**kwargs: Any) -> dict:
            result = original_get_params(**kwargs)
            metadata = kwargs.get("litellm_metadata") or kwargs.get("metadata") or {}
            info = metadata.get("model_info") or {}
            if info:
                result["model_info"] = info
            return result
        guarded_get_params._redpill_guard = True
        get_litellm_params.get_litellm_params = guarded_get_params

    original_get_client = OpenAIChatCompletion._get_openai_client
    if not getattr(original_get_client, "_redpill_guard", False):
        def guarded_get_client(self: Any, *args: Any, **kwargs: Any) -> Any:
            endpoint = kwargs.get("api_base")
            if isinstance(endpoint, str) and urlsplit(endpoint).hostname == "tee.redpill.ai":
                return build_redpill_tee_client(**kwargs)
            return original_get_client(self, *args, **kwargs)
        guarded_get_client._redpill_guard = True
        OpenAIChatCompletion._get_openai_client = guarded_get_client

    import litellm.proxy.proxy_server as proxy
    from litellm.router import Router
    for method_name in ("upsert_deployment", "add_deployment"):
        original = getattr(Router, method_name)
        if not getattr(original, "_redpill_guard", False):
            def guarded(self: Any, deployment: Any, _original: Any = original) -> Any:
                values = dict(effective_params(deployment.litellm_params))
                values["_redpill_credential_source"] = "runtime"
                validate_redpill_deployment(values, deployment.model_info or {})
                return _original(self, deployment)
            guarded._redpill_guard = True
            setattr(Router, method_name, guarded)

    original_get_config = proxy.ProxyConfig.get_config
    if not getattr(original_get_config, "_redpill_guard", False):
        async def guarded_config(self: Any, *args: Any, **kwargs: Any) -> Any:
            config = await original_get_config(self, *args, **kwargs)
            validate_redpill_config(config)
            return config
        guarded_config._redpill_guard = True
        proxy.ProxyConfig.get_config = guarded_config
    return True


class RedPillTee(CustomLogger):
    """Applying the public-PKI transport at callback load is the feature."""

    def __init__(self) -> None:
        super().__init__()
        apply_redpill_tee_trust()


redpill_tee_logger = RedPillTee()
