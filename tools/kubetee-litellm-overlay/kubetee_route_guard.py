# KubeTEE route guard for the LiteLLM gateway.
#
# Baked into ghcr.io/kubetee-ai/litellm-database:<tag> (NOT ConfigMap-mounted
# — see tools/kubetee-litellm-overlay/README.md). Registered as a custom
# callback in litellm_settings.callbacks:
#   callbacks: ["dynamic_rate_limiter_v3", "prometheus",
#               "kubetee_attestation.kubetee_attestation_logger",
#               "kubetee_route_guard.kubetee_route_guard_logger"]
#
# What it does
# ------------
# Blocks GET /v1/videos (video LIST) for every key, including admin.
#
# Why: the backend (vllm-omni) serves GET /v1/videos from a GLOBAL in-memory
# store with no per-key scoping — any authenticated key can enumerate every
# tenant's video jobs (IDs, statuses, prompts in metadata). Per-key
# allowed_routes cannot split GET from POST on the same path. Individual
# video retrieval by unguessable ID (returned only to the creator by
# POST /v1/videos) remains the supported access model:
#   POST   /v1/videos            create -> returns {id, status: queued}
#   GET    /v1/videos/{id}        poll status
#   GET    /v1/videos/{id}/content  download MP4 (1h TTL on the backend)
#   DELETE /v1/videos/{id}        already 405 at the proxy; TTL sweeps it
#
# kubetee.8 (2026-10-07): also 404s video STATUS/CONTENT polls whose
# video_id cannot resolve to a router deployment. Hit 2026-10-06 20:10-20:20
# UTC (Belarel): 148x 500 "OpenAIException - Cannot connect to host
# api.openai.com:443 ssl:True [SSLCertVerificationError ...]" — the client
# polled GET /v1/videos/{id} with raw/unresolvable IDs; the proxy's
# video_status endpoint defaults custom_llm_provider to "openai" when the
# id does not decode, route_llm_request bypasses the router when data has
# no model, and the direct litellm.avideo_status path then targets
# api.openai.com/v1/videos (openai transformation get_complete_url default).
# The TDX pod trusts only the east-west CA (/certs/ca.pem), so the TLS
# handshake fails cert verification -> InternalServerError 500. Returning a
# clean 404 "video not found" for unresolvable ids avoids the outbound call
# entirely (and the provider leak toward api.openai.com); resolvable ids
# (decode -> model_id -> resolve_model_name_from_model_id) still poll
# normally. avideo_content is covered by the same rule — content of an
# unresolvable id hits the same fallback path.
#
# How: CustomLogger.async_pre_call_hook fires inside
# base_process_llm_request BEFORE provider routing, with a call_type unique
# to the list route ("avideo_list" — distinct from "avideo_generation" used
# by POST). Raising HTTPException there converts cleanly to a client-facing
# ProxyException (common_request_processing._handle_llm_api_exception ->
# proxy_exception_from_http_exception preserves the status code).
# Verified against litellm 1.103.2/1.103.3 AND 1.104.0 (the new
# skip_guardrails param defaults False and only skips guardrail pipelines,
# not plain CustomLogger callbacks).

import threading
from typing import Any

from fastapi import HTTPException, status
from litellm.integrations.custom_logger import CustomLogger

# call_types blocked for ALL keys (admin included). Blocklist, not
# allowlist — new endpoints stay reachable by default.
_BLOCKED_CALL_TYPES = frozenset({"avideo_list"})

# Video poll call_types that fall through to a provider-direct call when the
# id cannot resolve to a router deployment (route_llm_request: data has no
# "model" -> getattr(litellm, route_type) directly). On the direct path the
# provider defaults to openai (videos/main.py: "or 'openai'") and the openai
# transformation targets https://api.openai.com — unreachable from the TDX
# pod (east-west-only CA trust). 404 these before routing instead.
_VIDEO_POLL_CALL_TYPES = frozenset({"avideo_status", "avideo_content"})

_RULES_LOCK = threading.Lock()


def _is_blocked(call_type: Any) -> bool:
    with _RULES_LOCK:
        return call_type in _BLOCKED_CALL_TYPES


def _video_id_is_resolvable(video_id: Any) -> bool:
    """True when the video_id decodes to a provider AND a model_id.

    Mirrors litellm.types.videos.utils.decode_video_id_with_provider:
    a gateway-issued id is "video_" + base64("litellm:custom_llm_provider:
    <p>;model_id:<m>;video_id:<raw>"). Anything else (raw backend id, id
    from another gateway) decodes with provider/model_id None and would
    take the openai-default fallback path.
    """
    if not isinstance(video_id, str) or not video_id:
        return False
    try:
        from litellm.types.videos.utils import (
            VIDEO_ID_PREFIX,
            decode_video_id_with_provider,
        )

        if video_id.startswith(VIDEO_ID_PREFIX):
            decoded = decode_video_id_with_provider(video_id)
            return bool(decoded.get("custom_llm_provider")) and bool(decoded.get("model_id"))
        return False
    except Exception:
        # Malformed base64 etc. — treat as unresolvable (404).
        return False


class KubeTEERouteGuard(CustomLogger):
    """Rejects blocked call_types before routing. No other behavior."""

    async def async_pre_call_hook(
        self,
        user_api_key_dict: Any,
        cache: Any,
        data: dict,
        call_type: Any,
    ) -> None:
        if _is_blocked(call_type):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "message": f"The requested route is not available: {call_type}",
                        "type": "invalid_request_error",
                        "param": None,
                        "code": "route_not_available",
                    }
                },
            )
        if call_type in _VIDEO_POLL_CALL_TYPES and not _video_id_is_resolvable(
            data.get("video_id") if isinstance(data, dict) else None
        ):
            # Router-unresolvable poll: without this the proxy defaults the
            # provider to openai and dials api.openai.com, which 500s with a
            # TLS verification error from the TDX pod. Clean 404 instead.
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "message": f"Video not found: {data.get('video_id', '')}",
                        "type": "invalid_request_error",
                        "param": None,
                        "code": "video_not_found",
                    }
                },
            )


kubetee_route_guard_logger = KubeTEERouteGuard()
