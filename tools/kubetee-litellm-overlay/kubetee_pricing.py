# KubeTEE static cost-map entries for the LiteLLM gateway.
#
# Baked into ghcr.io/kubetee-ai/litellm-database:<tag> (same measured-image
# pattern as kubetee_route_guard — see tools/kubetee-litellm-overlay/README.md).
# Registered as a custom callback in litellm_settings.callbacks:
#   callbacks: ["dynamic_rate_limiter_v3", "prometheus",
#               "kubetee_attestation.kubetee_attestation_logger",
#               "kubetee_route_guard.kubetee_route_guard_logger",
#               "kubetee_pricing.kubetee_pricing_logger"]
#
# What it does
# ------------
# Registers per-image prices under the exact `litellm.model_cost` keys that
# `default_image_cost_calculator` probes, so image-generation spend tracks
# correctly under honest (non-masqueraded) model names.
#
# Why (Belarel audit #11 + 2026-10-05 migration)
# ----------------------------------------------
# `black-forest-labs/flux.2-klein-4b` used to masquerade as
# `openai/dall-e-2` because that was the only model string that both (a) let
# `response_format=b64_json` through the OpenAI image param validation and
# (b) hit a cost-map entry. The dall-e-2 name leaked into client-facing
# usage rows (audit finding) while billing nothing.
#
# On LiteLLM 1.103.x the honest setup (`custom_llm_provider=hosted_vllm` +
# model `hosted_vllm/black-forest-labs/FLUX.2-klein-4B`) passes params
# through unvalidated, but `default_image_cost_calculator` IGNORES the
# deployment's own `input_cost_per_image` (litellm_params pricing) — it only
# reads static `litellm.model_cost` keys:
#   {quality}/{provider}/{size}/{model-without-provider}
#   {provider}/{size}/{model-without-provider}
#   {quality}/{size}/{model-last-segment}
#   {size}/{model-last-segment}
#   {model}
#   {model-without-provider}          <- black-forest-labs/FLUX.2-klein-4B
# Upstream fixed this in #39311 ("honor deployment pricing for image
# generation", 4bcdaf3d4b, first released in 1.104.0): `model_info` is now
# threaded through `route_image_generation_cost_calculator` and the
# deployment's price table wins. When the gateway moves to >= 1.104, the
# `input_cost_per_image` already stored on the DB row
# (c4eb8424-ad8b-4c37-bacd-ced0b18f1d5a, set 2026-10-05) starts working on
# its own and this module becomes redundant — keep it one release as a
# belt-and-suspenders (the deployment price and these entries are the same
# $0.05), then drop it at the next base bump.
#
# How
# ---
# Import-time `litellm.register_model(...)` with
# `persist_across_reloads=True` (the default): the entries are replayed by
# `reapply_runtime_model_cost_registrations()` after every cost-map refresh
# (adopt_model_cost_map -> reapply), so an upstream price-data reload cannot
# silently erase them. Verified: registration + reload + call -> 0.05.
#
# The CustomLogger instance exists only because the proxy's callback loader
# imports `<module>.<name>` and calls it on request paths; registration is
# a pure import side effect. (Importing this module via `callbacks:` also
# guarantees it loads AFTER `litellm` is fully initialized — a bare
# sitecustomize import would race the cost-map fetch on boot.)

from litellm.integrations.custom_logger import CustomLogger

# key -> cost-map entry. The key is the exact
# `model_name_without_custom_llm_provider` probe of
# default_image_cost_calculator for a deployment whose litellm_params.model
# is "hosted_vllm/black-forest-labs/FLUX.2-klein-4B" (register_model remaps
# the provider-prefixed spelling onto the same entry, so one key suffices).
# The calculator multiplies by n.
STATIC_MODEL_COST = {
    "black-forest-labs/FLUX.2-klein-4B": {
        "input_cost_per_image": 0.05,
        "mode": "image",
        "litellm_provider": "hosted_vllm",
    },
}


def _register_static_pricing() -> None:
    import litellm

    litellm.register_model(model_cost=dict(STATIC_MODEL_COST))


_register_static_pricing()


class KubeTEEPricing(CustomLogger):
    """No-op logger; the registration above is the entire feature."""


kubetee_pricing_logger = KubeTEEPricing()
