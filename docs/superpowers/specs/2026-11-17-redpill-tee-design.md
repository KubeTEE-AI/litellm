# RedPill TEE model support: approved design

## Intent

Serve RedPill's `qwen/qwen3.8-27b` through `https://tee.redpill.ai/v1` as the first
of many Opt-in external TEE deployments. Retired KubeTEE backends stay retired.
RedPill is not a remediation for the 2026-11-13 Oakland retirement.

## Constraints and trust boundary

- The live gateway is Fleet `production` `litellm-helm-production`, cluster
  `eu-lu-luxembourg-133`, namespace `litellm`, two TDX guests.
- No NetworkPolicy selects LiteLLM; host TLS 1.3 checks reached the intended
  RedPill endpoints. Public outbound calls use an isolated certifi client,
  while the private East-West CA configured in Fleet remains internal-only.
- The gateway keeps certifi support only in the measured overlay; do not widen
  the existing `ssl_verify` setting for any other model.
- Only the exact HTTPS host `tee.redpill.ai`, using `https` for verification,
  gets a public CA. Equivalent URLs with changed host/port or other endpoints
  are rejected at registration. Final traffic must still go through standard
  TLS certificate and hostname verification.
- Customer and upstream model names are exactly RedPill catalog names
  (initially `qwen/qwen3.8-27b`). Internally, LiteLLM's native
  `openai/qwen3.8-27b` sends `qwen/qwen3.8-27b` upstream; there is no new
  custom provider prefix or custom response/streaming implementation.
- Every `origin=redpill,tee` row is checked by the measured `redpill_tee`
  policy helper and the operator callback `redpill_tee.redpill_tee_logger`.
  Registration rejects plaintext keys, public non-TEE hosts, unsafe partial
  patches, fail-open metadata, and cross-origin fallbacks.
- An optional explicit port 443/trailing slash remains supported only on the
  exact HTTPS host. No username/password, alternate port, query or fragment.
- No force-deletes, node reboots, in-cluster image builds, unapproved image
  tags, or weakening of `ExecProcessRequest=false`.

## Approach

1. `redpill_tee.redpill_tee_logger` is the callback/startup hook for explicitly
   tagged rows. It intercepts only the native OpenAI client factory, preserving
   the upstream OpenAI transport/parser with a dedicated certifi-backed client;
   other callers and KubeTEE KBS
   trust remain unchanged. `num_retries: 0` prevents cross-origin retries.
   **Implementation is narrowed to the native OpenAI adapter's client factory—no
   custom provider is registered and its full streaming/parser contract remains unchanged.**
2. `redpill_tee.resolve_redpill_api_base` accepts any upstream model name but
   only `origin=redpill,tee` deployment metadata and the exact TEE endpoint.
   Registration guards apply to config, `add_deployment`, `upsert_deployment`,
   model creation and both update forms. Management writes must use only
   `os.environ/REDPILL_API_KEY`; the router sees its resolved Secret value.
   Routed clients must never carry KBS client certificates.
4. `upstream_tracking: receipt-forwarded-unverified` is intentionally honest:
   TEE-only host routing is not cryptographic attestation or receipt verification.
   Receipt observability does not itself bind TLS to a quote or verify its event log.
5. Signed CI on protected `kubetee-prod` produces a new immutable tag/digest
   and provenance. Fleet, root Rego, canonical TOML and the Fleet encoded blob
   are updated as a single measured unit and checked by `verify-litellm-policy.py`.
4. `REDPILL_API_KEY` goes into a manual secret `redpill`, then a config row keyed
   by `os.environ/REDPILL_API_KEY`. No raw key is committed or printed.
5. Rolling one guest at a time, verify model allowlisting/tag routing, streaming,
   RedPill `upstream.verified`, a receipt, error confinement, existing rows, and
   independent KubeTEE attestation. Access groups/team enforcement are covered
   by verification, not implied by tags.

## LiteLLM APIs Only (user directive 2026-11-17)

**NEVER write to LiteLLM PostgreSQL, Prisma, or use raw SQL to create or update a
model. No `/model/new`, `/model/update`, or live gateway writes have yet happened.**

1. `GET /v1/model/info`, with the Luxembourg master key, is the initial inventory. It does NOT validate remote catalogs or TEE origin. If Luxembourg's local Qwen admission gate rejects the planned group, obtain explicit user scope to temporarily RedPill tag that existing group before registering it (do not widen it to every remote model).
2. Create the row only with `POST /model/new`, never direct datastore writes:
   `model_name: qwen/qwen3.8-27b`, `litellm_params.model: openai/qwen3.8-27b`,
   exact `api_base: https://tee.redpill.ai/v1`, `api_key: os.environ/REDPILL_API_KEY`, `num_retries: 0`, and the declared `model_info` tags, access group and fail-closed flags. A typed Ra-TLS inspector is separate from the model router and never forwards a request `model` name.
3. A non-200 response is reported as an API failure; fetch current row and router state, fix the payload, retry the management operation. Never use database access as a fallback.
4. Verify `GET /v1/model/info` after creation: public name and native adapter, base, pointer, tags, access groups, `num_retries: 0`, no fallbacks. Smoke a public chat completion and tokens stream. For updates, fetch the existing row first, include its `model_info.id`, and resend every retained list. No template-copy rows.
5. After the measured image rollout, model creation uses the above API without any SQL or direct Prisma access.

## Alternatives

- A NetworkPolicy `egress:` allowlist is separate optional hardening, not a
  substitute for endpoint-constrained TLS or model-registration policy.
- Add certifi to the global trust bundle or use `ssl_verify:false`: rejected;
  broadens the serving trust boundary or disables authenticated TLS.
- Use `EXPERIMENTAL_OPENAI_BASE_LLM_HTTP_HANDLER`: rejected; changes the whole
  provider surface including streaming for an error key belongs to one host.

## Confirmed first deployment

- Public model: `qwen/qwen3.8-27b` with `model="openai/qwen/qwen3.8-27b"`.
- Library catalog: add `openai/qwen/qwen3.8-27b` (1,000,000-token context,
  262,144 max output, $0.20/M input, $2.50/M output, $0.05/M cached input).
- Confirmed upstream `is_tee:true` and live HTTP 200 with receipt on 2026-11-17.
- `tags=[origin=redpill, tee]` with `allow_fail_open:false`; no `default` tag.
- Access group `origin-redpill-models`; no automatic fallback or SayGM offer.
- Live model price/private upstream trust is checked before registration.
