# KubeTEE LiteLLM Gateway Overlay

Derived image for the `llm.kubetee.ai` gateway (na-us-oakland-56, CPU-TDX
Kata pod). Everything the gateway runs that is **not** upstream LiteLLM
ships in this image so it is covered by the TDX measurement chain:

```
git (this repo, branch kubetee-1.103.3, tag v1.103.3)
  -> GitHub Actions (.github/workflows/build-litellm-overlay.yaml)
  -> ghcr.io/kubetee-ai/litellm-database:<upstream>-kubetee.N
  -> measured container allowlist (nim/eastwest/policy-litellm.rego,
     re-encoded into cc_init_data -> measured into the TD)
```

## Why this exists (2026-10-05)

The gateway's custom modules used to be ConfigMap-mounted via subPath into
`/app/.venv/lib/python3.13/site-packages/`:

- `sitecustomize.py` — east-west client-cert chain for the httpx 0.28
  OpenAI path (ssl_verify CA path + `load_cert_chain`).
- `kubetee_attestation.py` — `GET /v1/attestation` + inline
  `X-KubeTEE-Nonce` evidence (source of truth: the root repo's
  `nim/eastwest/kubetee_attestation.py` — keep in sync).

The TDX quote proves the guest, kernel params, init-data policy, and the
image allowlist — but the ConfigMap-injected Python was **unmeasured**:
anyone with ConfigMap write access could swap the modules (including the
attestation module itself) without changing any measurement. Baking them
into an image built from this repo closes that gap.

## Modules

| Module | Purpose |
|---|---|
| `kubetee_route_guard.py` | Blocks `GET /v1/videos` (list) for every key incl. admin. The backend (`vllm-omni`) serves the list from a global in-memory store with no per-key scoping — any authenticated key could enumerate every tenant's video jobs. `CustomLogger.async_pre_call_hook` fires on `call_type="avideo_list"` before routing; raising `HTTPException(404)` there converts to a clean client-facing `ProxyException`. Create/status/content by unguessable ID remain open. |
| `kubetee_attestation.py` | Client-facing TDX attestation (`GET /v1/attestation?nonce=`, inline `X-KubeTEE-Nonce` on chat, TLS-possession proof). Identical bytes to the root repo's `nim/eastwest/kubetee_attestation.py` at the time of the first build. |
| `sitecustomize.py` | Loads the east-west client chain into the shared SSLContext when `ssl.create_default_context` is called with the east-west CA. |
| `kubetee_pricing.py` | Static `litellm.model_cost` entries (import-time `litellm.register_model`, `persist_across_reloads=True`) so image-generation spend tracks under honest model names on 1.103.x. Stock 1.103.x ignores the deployment's `input_cost_per_image` for image calls (`default_image_cost_calculator` reads static keys only); upstream fixed in #39311 (first in 1.104.0). Currently carries `black-forest-labs/FLUX.2-klein-4B` @ $0.05/image (DB row `c4eb8424`, migrated off the `dall-e-2` masquerade 2026-10-05) and `MiniMax-H3` @ $0.08/s video. **Drop this module one release after the base bumps to >= 1.104** — the DB row's `input_cost_per_image` then takes over. |
| `kubetee_glm_effort.py` | Validates/maps `reasoning_effort` for GLM models (Belarel audit item 10). `CustomLogger.async_pre_call_hook` before provider routing. GLM-5.3/Flash are always-on reasoners: `low`/`high`/`max` pass through, `none` gets a 400 (`reasoning_effort_not_supported`) because the client expects thinking OFF and the model cannot (v0.5.20 degenerate-loops on `none`), and `medium`/`minimal`/unknown **map to `max`** — the official card semantics ("defaults to max if… set to any other value"), so SDKs defaulting to `medium` keep working. GLM-5.2 keeps the native `enable_thinking` toggle: `none` → `chat_template_kwargs={"enable_thinking": false}`, `high`/`max` pass, and `low`/`medium`/`minimal`/unknown **map to `high`** (kubetee.7) — the template accepts high/max only and coerces everything else to `max`, so `high` is the only faithful downgrade path for clients asking for less thinking (kubetee.6's 400 broke a live client sending `effort=low`). Verified live 2026-10-06 at temperature 0 + unit table in the module header. |

## Registration

In the Fleet values (oakland overlay only — a failed callback import
crashes the proxy at startup):

```yaml
proxy_config:
  litellm_settings:
    callbacks: ["dynamic_rate_limiter_v3", "prometheus",
                "kubetee_attestation.kubetee_attestation_logger",
                "kubetee_route_guard.kubetee_route_guard_logger",
                "kubetee_pricing.kubetee_pricing_logger",
                "kubetee_glm_effort.kubetee_glm_effort_logger"]
```

Registration is import-time; the entry point instance names are
`kubetee_attestation_logger`, `kubetee_route_guard_logger`,
`kubetee_pricing_logger`, and `kubetee_glm_effort_logger`. (For
`kubetee_pricing` the callback registration is what triggers the import —
the `register_model` call in module scope is the actual feature.)

## Tags

`<upstream-version>-kubetee.N` — e.g. `1.103.3-kubetee.1`. The base tag
(default `1.103.3`) is overridable per run via `workflow_dispatch` inputs.
**Never reuse a tag** (a node with `imagePullPolicy: IfNotPresent` caches
by tag; overwriting a tag leaves stale layers on nodes — same rule as the
kata-deploy CSI `-kubetee3` incident).

## Build / verify

Pushes to `tools/kubetee-litellm-overlay/**` on branch `kubetee-1.103.3`
build automatically; `workflow_dispatch` allows a custom tag + base.

CI gates:

1. Modules present, non-empty, contain their markers
   (`avideo_list` block rule, `KubeTEEAttestationLogger`, 404 status,
   `KubeTEEGlmEffort` + `reasoning_effort_not_supported` + `enable_thinking`).
2. Smoke test: modules import cleanly against the pulled base image
   (`docker run base python -c "import kubetee_route_guard, ..."`).
3. Post-push verify: modules import from the venv site-packages inside the
   pushed image, and file sizes are printed for the build log.

## Rollout coupling

The measured container allowlist (`policy-litellm.rego` →
`initdata-litellm.toml` → `cc_init_data` pod annotation) must be updated
with the new image tag **in the same Fleet change** — the policy allows
only the exact image-name+tag entries it carries, so a new tag without a
policy update wedges the pod at `CreateContainer` (and vice versa: the
old `berriai/litellm-database:1.103.2` entry must stay until the rollout
completes). Rollout order that works:

1. Add the new image entry to the policy allowlist + re-encode initdata.
2. Swap the image in the Fleet values.
3. Rollout completes; old entry becomes removable (keep it one release
   for rollback, then prune).

Verification after rollout (user key):

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://llm.kubetee.ai/v1/videos -H "Authorization: Bearer $KEY"
# expect 404 (route_not_available)

# create + poll + download still work:
curl -s -X POST https://llm.kubetee.ai/v1/videos -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" -d '{"model": "minimax/h3", "prompt": "...", "seconds": 5}'
# -> {"id": "video_...", "status": "queued", ...}
```

## Updating the modules

1. Edit the module in this directory.
2. Bump the `-kubetee.N` suffix (never reuse).
3. Push to `kubetee-1.103.3` (or dispatch with a custom tag).
4. Update `nim/eastwest/kubetee_attestation.py` in the root repo to match
   (source-of-truth sync), and the Fleet values if registration changed.
5. Update the policy allowlist if the image tag changed (see above).
