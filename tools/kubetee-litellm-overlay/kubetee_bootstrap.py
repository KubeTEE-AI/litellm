"""Gateway startup: east-west mTLS material before LiteLLM starts.

Runs from the overlay's entrypoint (kubetee-entrypoint.sh) before LiteLLM:

1. East-west mTLS material -> container scratch (kubetee_eastwest;
   fail-closed — nothing serves without its mTLS material).
2. Boot-time Trustee EAR -> /run/kubetee-eastwest/boot-ear.jwt (best-effort,
   additive — minted over the east-west key inside fetch_eastwest; when it
   is absent the v1 bundle simply omits ``appraisal``).

Failing exits non-zero so the container fails and kubelet retries the pod.
Nothing here writes key material outside the guest.

Scope note (2026-10-24 design re-scope): the client-facing serving cert is
cert-manager litellm-tls (/etc/tls — public TLS is not worth a DNS-zone
credential in every guest). Strict per-boot in-TEE key custody belongs to
the EAST-WEST identity: the attestation-gated signer follow-up turns this
entrypoint's step 1 into per-boot keygen + EAR-bound short-lived cert, and
the boot EAR cache (minted over that east-west key — see kubetee_ear).
"""

from __future__ import annotations

import asyncio
import sys


async def main() -> None:
    import kubetee_eastwest

    await kubetee_eastwest.fetch_eastwest()
    print("kubetee bootstrap: east-west material ready", flush=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as error:  # noqa: BLE001 - fail-closed with a clear reason
        print(f"kubetee bootstrap failed (fail-closed): {error}", file=sys.stderr, flush=True)
        sys.exit(1)
