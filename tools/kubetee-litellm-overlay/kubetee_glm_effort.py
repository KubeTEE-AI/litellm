# KubeTEE GLM reasoning-effort contract enforcement for the LiteLLM gateway.
#
# Baked into ghcr.io/kubetee-ai/litellm-database:<tag> (same measured-image
# pattern as kubetee_route_guard — see tools/kubetee-litellm-overlay/README.md).
# Registered as a custom callback in litellm_settings.callbacks:
#   callbacks: ["dynamic_rate_limiter_v3", "prometheus",
#               "kubetee_attestation.kubetee_attestation_logger",
#               "kubetee_route_guard.kubetee_route_guard_logger",
#               "kubetee_pricing.kubetee_pricing_logger",
#               "kubetee_glm_effort.kubetee_glm_effort_logger"]
#
# What it does
# ------------
# Validates and maps `reasoning_effort` for GLM-family models BEFORE provider
# routing, so unsupported values fail fast with a clear 400 instead of being
# silently coerced by the backend chat template.
#
# Why (Belarel audit item 10, 2026-10-06)
# ----------------------------------------
# The GLM-5.3 / GLM-5.3-Flash chat templates accept `reasoning_effort` in
# {low, high, max} ONLY, and silently coerce every other value (including
# "none" and "minimal") to "max". These are always-on reasoners: the
# GLM-4.5-era `enable_thinking` toggle is gone; zai replaced it with a
# "Reasoning Effort: <level>" prompt header. Verified live 2026-10-06 at
# temperature 0 through the gateway:
#   - z-ai/glm-5.3 (B200, sglang v0.5.20): effort=none -> deterministic
#     degenerate reasoning loop (2000-token, empty content, finish=length);
#     low/high/max all work (answer preserved, rlen=0 on trivial prompts).
#   - z-ai/glm-5.3-flash (H200, nightly 20261005): effort=none is
#     indistinguishable from baseline (coerced to max, still thinks);
#     low/high/max work.
#   - z-ai/glm-5.2 (nvfp4, sglang v0.5.20): the template STILL has
#     enable_thinking — "none" suppresses thinking cleanly; "low" is
#     coerced to max (the 5.2 template only accepts high/max).
#
# The mapping enforced here:
#   glm-5.3 / glm-5.3-flash:
#     low | high | max   -> pass through unchanged (template honors natively)
#     medium | minimal | * -> mapped to "max" — the OFFICIAL card semantics:
#                           "defaults to max if not passed (or if set to any
#                           other value)" (zai-org/GLM-5.3 README, Note §1).
#                           No 400: z.ai's own contract is silent fallback,
#                           and SDKs that default to medium must keep working.
#     none              -> 400 (always-on reasoner; "none" on v0.5.20 is a
#                           deterministic degenerate reasoning loop, and a
#                           client asking for NO thinking must be told, not
#                           silently maxed)
#   glm-5.2:
#     none              -> chat_template_kwargs["enable_thinking"] = False
#                           (native no-think), top-level effort dropped so
#                           the template does not coerce it to "max"
#     high | max        -> pass through
#     medium | minimal | * -> 400 (the 5.2 template accepts high/max only;
#                           mapping medium to a thinking level would be our
#                           invention — reject with the supported list)
#
# How: CustomLogger.async_pre_call_hook fires inside
# base_process_llm_request BEFORE provider routing. Mutating `data` in place
# is the documented request-rewrite path; raising HTTPException converts to a
# clean client-facing ProxyException (same mechanism as kubetee_route_guard).
# Relevant upstream SGLang context: #39227 (glm53 always-think parsing rule),
# #37524 (GLM-5.3 tracker), #40843/#41939 (degenerate reasoning loops on
# B200 + spec decode), #33155 (top-level enable_thinking still unmerged).
# 2026-10-06 revision: real traffic (SDKs defaulting to effort=medium) hit
# the original strict 400s within the hour. Posture re-checked against the
# zai-org model cards and revised: GLM-5.3 follows the card's documented
# any-other-value->max fallback (medium/minimal pass as max); GLM-5.2 keeps
# the strict rejection (medium->high would be invented semantics). "none"
# stays a hard 400 on GLM-5.3 — it is the one value a client legitimately
# expects to suppress thinking, and silent max there is a cost/latency trap.

from typing import Any

from fastapi import HTTPException, status
from litellm.integrations.custom_logger import CustomLogger

# Match on the final path segment, case-insensitive, so both the public alias
# ("z-ai/glm-5.3") and the routed deployment model ("openai/zai-org/GLM-5.3")
# hit the rule.
_GLM53_MODELS = frozenset({"glm-5.3", "glm-5.3-flash"})
_GLM52_MODELS = frozenset({"glm-5.2"})
_GLM53_EFFORTS = ("low", "high", "max")
_GLM52_EFFORTS = ("high", "max", "none")


def _model_segment(model: Any) -> str:
    if not isinstance(model, str):
        return ""
    return model.rsplit("/", 1)[-1].strip().lower()


def _extract_effort(data: dict) -> Any:
    effort = data.get("reasoning_effort")
    if effort is None:
        # Defensive: some code paths stash provider params in optional_params.
        optional = data.get("optional_params")
        if isinstance(optional, dict):
            effort = optional.get("reasoning_effort")
    if isinstance(effort, str):
        return effort.lower()
    return effort


def _reject(model: Any, effort: Any, allowed: tuple) -> None:
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={
            "error": {
                "message": (
                    f"reasoning_effort={effort!r} is not supported on {model}. "
                    f"Supported values: {', '.join(allowed)}."
                ),
                "type": "invalid_request_error",
                "param": "reasoning_effort",
                "code": "reasoning_effort_not_supported",
            }
        },
    )


class KubeTEEGlmEffort(CustomLogger):
    """Validates/maps reasoning_effort for GLM models. No other behavior."""

    async def async_pre_call_hook(
        self,
        user_api_key_dict: Any,
        cache: Any,
        data: dict,
        call_type: Any,
    ) -> None:
        segment = _model_segment(data.get("model"))
        if segment not in _GLM53_MODELS and segment not in _GLM52_MODELS:
            return

        effort = _extract_effort(data)
        if effort is None:
            return

        if segment in _GLM53_MODELS:
            if effort in _GLM53_EFFORTS:
                # Template honors low/high/max natively — pass through.
                return
            if effort == "none":
                # The one value a client expects to suppress thinking.
                # GLM-5.3 cannot — tell them, don't silently max (a 2000-token
                # degenerate reasoning loop on v0.5.20, and a cost trap on all).
                _reject(data.get("model"), effort, _GLM53_EFFORTS)
            # Card semantics (zai-org/GLM-5.3 README): "defaults to max if
            # not passed (or if set to any other value)". medium/minimal/
            # anything else -> max, no error — SDKs defaulting to medium
            # keep working exactly as they would against z.ai directly.
            data["reasoning_effort"] = "max"
            optional = data.get("optional_params")
            if isinstance(optional, dict):
                optional["reasoning_effort"] = "max"
            return

        # GLM-5.2: honor "none" via the template's native enable_thinking.
        if effort == "none":
            ctk = dict(data.get("chat_template_kwargs") or {})
            ctk["enable_thinking"] = False
            data["chat_template_kwargs"] = ctk
            optional = data.get("optional_params")
            if isinstance(optional, dict):
                optional["chat_template_kwargs"] = dict(optional.get("chat_template_kwargs") or {})
                optional["chat_template_kwargs"]["enable_thinking"] = False
                optional.pop("reasoning_effort", None)
            data.pop("reasoning_effort", None)
            return
        if effort in _GLM52_EFFORTS:
            return
        # GLM-5.2: high/max/none only. medium/minimal/low are NOT in the
        # template's accepted set and mapping them to a thinking level would
        # be invented semantics — reject with the supported list.
        _reject(data.get("model"), effort, _GLM52_EFFORTS)


kubetee_glm_effort_logger = KubeTEEGlmEffort()
