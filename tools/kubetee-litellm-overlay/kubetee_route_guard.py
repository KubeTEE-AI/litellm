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
_RULES_LOCK = threading.Lock()


def _is_blocked(call_type: Any) -> bool:
    with _RULES_LOCK:
        return call_type in _BLOCKED_CALL_TYPES


class KubeTEERouteGuard(CustomLogger):
    """Rejects blocked call_types before routing. No other behavior."""

    def async_pre_call_hook(
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


kubetee_route_guard_logger = KubeTEERouteGuard()
