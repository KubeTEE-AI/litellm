"""East-west mTLS material fetched at container start into container-local scratch.

Plan ``eastwest-keys-strict``: the east-west client key/cert + CA never touch
the host-shared ``/certs`` emptyDir (a virtio-fs share the host can read).
The gateway's own entrypoint fetches them through the in-guest CDH into the
container's scratch (``KUBETEE_EASTWEST_DIR``, default ``/run/kubetee-eastwest``).
This is the channel that carries the gateway's authorization to privileged
backends — the 2026-10-24 re-scope puts STRICT per-boot in-TEE custody here
(the attestation-gated signer mints this identity from a per-boot key against
a Trustee EAR), while the client-facing serving cert stays cert-manager.
This retires the ``fetch-certs`` init container and its emptyDir for the
gateway; backend guests adopt at their next natural rolls.

Resource paths (Trustee, via the in-guest CDH ``/cdh/resource/…``):

    default/eastwest-ca/ca.pem
    default/eastwest-litellm/tls.crt + tls.key      (role litellm)
    default/eastwest-nim/tls.crt + tls.key          (role nim-terminator)

Retry semantics match the retired fetch-certs init container: 180 attempts at
2 s (~6 min) for the AA/KBS flow to come up, then fail-closed — the container
exits non-zero and kubelet retries the pod (nothing serves without its mTLS
material).
"""

from __future__ import annotations

import asyncio
import os
from typing import Final

CDH_BASE: Final = os.environ.get("KUBETEE_CDH_BASE", "http://127.0.0.1:8006")
EASTWEST_DIR: Final = os.environ.get("KUBETEE_EASTWEST_DIR", "/run/kubetee-eastwest")
ROLE: Final = os.environ.get("EASTWEST_ROLE", "litellm")

_RESOURCES: Final[dict[str, tuple[tuple[str, str], ...]]] = {
    "litellm": (
        ("default/eastwest-ca/ca.pem", "ca.pem"),
        ("default/eastwest-litellm/tls.crt", "tls.crt"),
        ("default/eastwest-litellm/tls.key", "tls.key"),
    ),
    "nim-terminator": (
        ("default/eastwest-ca/ca.pem", "ca.pem"),
        ("default/eastwest-nim/tls.crt", "tls.crt"),
        ("default/eastwest-nim/tls.key", "tls.key"),
    ),
}

_FETCH_ATTEMPTS: Final = 180
_FETCH_INTERVAL_S: Final = 2.0


class EastWestError(RuntimeError):
    """Raised when the east-west material cannot be established."""


async def _fetch(http: object, path: str) -> bytes:
    url = f"{CDH_BASE}/cdh/resource/{path}"
    last: Exception | None = None
    for _ in range(_FETCH_ATTEMPTS):
        try:
            resp = await http.get(url)  # type: ignore[attr-defined]
            resp.raise_for_status()
            return resp.content
        except Exception as error:  # noqa: BLE001 - retry any transport/AA failure
            last = error
            await asyncio.sleep(_FETCH_INTERVAL_S)
    raise EastWestError(f"failed to fetch {path} after {_FETCH_ATTEMPTS} attempts: {last}")


async def fetch_eastwest() -> dict[str, str]:
    """Fetch the east-west material for $EASTWEST_ROLE into the scratch dir.

    Also writes the concatenated ``client.pem``/``server.pem`` pair the
    LiteLLM sync HTTPHandler path wants (``ssl_certificate``) — same bytes
    the retired fetch-certs.sh produced.
    """
    import httpx

    resources = _RESOURCES.get(ROLE)
    if resources is None:
        raise EastWestError(f"unknown EASTWEST_ROLE={ROLE}")
    os.makedirs(EASTWEST_DIR, mode=0o700, exist_ok=True)

    paths: dict[str, str] = {}
    async with httpx.AsyncClient(timeout=30.0) as http:
        for resource, name in resources:
            data = await _fetch(http, resource)
            dest = os.path.join(EASTWEST_DIR, name)
            mode = 0o600 if name.endswith(".key") else 0o644
            with open(dest, "wb") as f:
                f.write(data)
            os.chmod(dest, mode)
            paths[name] = dest

    pair_name = "client.pem" if ROLE == "litellm" else "server.pem"
    pair_path = os.path.join(EASTWEST_DIR, pair_name)
    with open(paths["tls.crt"], "rb") as crt, open(paths["tls.key"], "rb") as key, open(
        pair_path, "wb"
    ) as pair:
        key_pem = key.read()
        pair.write(crt.read() + key_pem)
    os.chmod(pair_path, 0o600)
    paths[pair_name] = pair_path

    # Boot-time EAR (best-effort): mint and cache the per-boot Trustee appraisal
    # over the east-west identity key so the v1 bundle can serve `appraisal`.
    # This is additive — the quote + binding stand without it, so any failure
    # (Trustee down, no pub key) just leaves `appraisal` absent. NOTE: this
    # call was missing entirely before 2026-10-27, which is why
    # `appraisal` was permanently absent (bootstrap_ear() had no caller).
    import kubetee_ear

    tee_pubkey = kubetee_ear.tee_pubkey_from_key_pem(key_pem)
    if tee_pubkey is not None:
        await kubetee_ear.bootstrap_ear(tee_pubkey)
    return paths
