# KubeTEE LiteLLM gateway overlay image.
#
# One layer of measured KubeTEE code on top of the upstream litellm-database
# runtime (wolfi + python3.13 venv at /app/.venv + prisma + pgbouncer).
# Everything the gateway runs that is NOT upstream litellm ships here, so
# the TDX measurement chain covers it:
#   git (KubeTEE-AI/litellm, branch kubetee-1.103.3) -> Actions -> ghcr.io/kubetee-ai/litellm-database:<tag>
#   -> measured container allowlist (policy-litellm.rego / initdata)
#
# Previously these modules were ConfigMap-mounted via subPath — unmeasured
# mutable state: the TDX quote proved the guest + the upstream image, but
# nothing bound the injected Python (including kubetee_attestation itself!)
# to git. See tools/kubetee-litellm-overlay/README.md.
#
# The venv site-packages path is the SAME one the subPath mounts targeted
# (/app/.venv/lib/python3.13/site-packages), so behavior is identical to the
# ConfigMap setup — the modules are just measured image content now.
#
# Tags: <upstream>-kubetee.N (e.g. 1.103.3-kubetee.1). Never reuse a tag.

ARG BASE_TAG=1.103.3
FROM ghcr.io/berriai/litellm-database:${BASE_TAG}

# kubetee_route_guard.py: blocks GET /v1/videos (global-store enumeration).
# kubetee_attestation.py: GET /v1/attestation + inline X-KubeTEE-Nonce evidence.
# kubetee_binding.py: the kubetee.attestation.v1 report_data construction
#   (JCS statement -> SHA-256, zero-padded), pinned by
#   tests/test_litellm/tools/kubetee-litellm-overlay/test_kubetee_binding.py
#   against the spec's conformance vectors. Served alongside the live
#   SHA512(nonce) binding until the gateway flip.
# sitecustomize.py: east-west client-cert chain for httpx 0.28 (ssl_verify CA
#   path + load_cert_chain into the shared SSLContext).
# kubetee_pricing.py: static cost-map entries so image-generation spend
#   tracks under honest model names on 1.103.x (upstream fix #39311 is
#   1.104+ only; keep one release after the base bump, then drop).
# kubetee_glm_effort.py: validates/maps reasoning_effort for GLM models
#   (Belarel audit item 10). GLM-5.3/Flash are always-on reasoners — the
#   chat template only accepts low/high/max and silently coerces anything
#   else (incl. "none") to "max"; the hook 400s unsupported values.
#   GLM-5.2 keeps the native enable_thinking toggle: "none" maps to
#   chat_template_kwargs={"enable_thinking": false} and is honored.
# kubetee_ear.py: Trustee EAR / AR4SI appraisal (the bundle's appraisal{}
#   block) + evidence.vm_config from the measured initdata + the tee_pubkey
#   JWK helper for the RCAR mint. The EAR is a per-boot RCAR mint; the
#   per-request nonce binding stays the v1 statement.
# kubetee_eastwest.py: east-west mTLS material -> container scratch
#   (/run/kubetee-eastwest) at startup, retiring the fetch-certs init
#   container + the host-shared /certs emptyDir (eastwest-keys-strict).
#   Strict per-boot in-TEE custody lands here under the attestation-gated
#   signer follow-up (per-boot key + EAR-bound short-lived cert).
# kubetee_bootstrap.py + kubetee-entrypoint.sh: run the east-west fetch
#   before the base entrypoint — fail-closed. Client-facing TLS stays
#   cert-manager (the ACME per-boot path was cut 2026-10-24).
COPY kubetee_route_guard.py kubetee_attestation.py kubetee_binding.py kubetee_ear.py kubetee_eastwest.py kubetee_bootstrap.py sitecustomize.py kubetee_pricing.py kubetee_glm_effort.py /app/.venv/lib/python3.13/site-packages/
COPY kubetee-entrypoint.sh /app/docker/kubetee-entrypoint.sh
RUN chmod 0755 /app/docker/kubetee-entrypoint.sh

# Wrap the base ENTRYPOINT (docker/prod_entrypoint.sh): strict key custody
# first, then exec the base entrypoint with the original CMD args.
ENTRYPOINT ["/app/docker/kubetee-entrypoint.sh"]
