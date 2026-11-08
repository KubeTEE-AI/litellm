#!/bin/sh
# KubeTEE gateway entrypoint — east-west mTLS material BEFORE LiteLLM starts.
#
#   1. east-west mTLS material  -> /run/kubetee-eastwest (CDH/Trustee, fail-closed)
#
# then exec the base litellm-database entrypoint (docker/prod_entrypoint.sh)
# with the original CMD args. Public TLS stays cert-manager litellm-tls
# (/etc/tls) per the 2026-10-24 re-scope — the ACME per-boot path is cut.
# Strict per-boot in-TEE custody lands on the EAST-WEST identity with the
# attestation-gated signer follow-up (per-boot key + EAR-bound cert here).
# This replaces the retired fetch-certs init container: the fetch lives in
# the using container now, and every byte lands in the container's own
# scratch — never the host-shared /certs emptyDir.
set -eu

/app/.venv/bin/python -m kubetee_bootstrap

exec /app/docker/prod_entrypoint.sh "$@"
