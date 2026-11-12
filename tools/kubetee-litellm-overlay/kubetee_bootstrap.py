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
    if __import__("os").environ.get("KUBETEE_GAMMA_ENABLED", "0") in {"1", "true"}:
        # This modifies only our in-process app, not a live deployment. It is
        # installed before LiteLLM loads any public routes and executes only
        # INSIDE ProxyStartupEvent AFTER native Prisma would have initialized.
        from contextlib import asynccontextmanager
        from litellm.proxy import proxy_server
        from kubetee_gamma_private_mtls import connect_public_claims, initialize_private_management
        # `app` is created with this exact bound function in the base image. Wrap
        # that bound hook AS WELL AS proxy_server.proxy_startup_event. The public
        # claim bridge must never be dropped when the bound object differs.
        router_hook = proxy_server.app.router.lifespan_context
        @asynccontextmanager
        async def gamma_lifespan(app):
            async with router_hook(app) as state:
                await initialize_private_management(kubetee_eastwest._fetch)
                await connect_public_claims()
                try:
                    yield state if state is not None else {}
                finally:
                    await proxy_server.app.state.kubetee_gamma_handler.close()
        proxy_server.proxy_startup_event = gamma_lifespan
        proxy_server.app.router.lifespan_context = gamma_lifespan
        import os
        os.environ["KUBETEE_EASTWEST_DIR"] = str(__import__("pathlib").Path(
            os.environ.get("KUBETEE_EASTWEST_DIR", "/run/kubetee-eastwest")))
    print("kubetee bootstrap: east-west material ready", flush=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as error:  # noqa: BLE001 - fail-closed with a clear reason
        print(f"kubetee bootstrap failed (fail-closed): {error}", file=sys.stderr, flush=True)
        sys.exit(1)
