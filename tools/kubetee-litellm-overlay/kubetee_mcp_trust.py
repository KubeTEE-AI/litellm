"""MCP-client trust scope — split the east-west trust anchor from public trust.

The gateway runs with a process-global ``litellm_settings.ssl_verify`` pointing
at the east-west CA (``/run/kubetee-eastwest/ca.pem``). That is deliberate: the
serving path (LiteLLM -> GLM :8443) must verify against the measured east-west
anchor and nothing else. The problem is that the same global is *shared*: the
outbound MCP client (``litellm.experimental_mcp_client.client.MCPClient``) has
never passed its own ``ssl_verify``, so its httpx2 client verifies **every**
upstream — including public MCP servers like DeepWiki and Hugging Face —
against the east-west CA alone. Those chains fail as::

    httpx2.ConnectError: [SSL: CERTIFICATE_VERIFY_FAILED]
    certificate verify failed: unable to get local issuer certificate

That is fail-closed TLS doing exactly its job (the alternative — widening the
global to a public CA — would silently open the east-west lane; do NOT do
that, see the 2026-10-07 ``api.openai.com`` incident in the route guard).

Fix (option 3, 2026-10-28): give the MCP lane its **own** trust context, with
the two lanes kept DISJOINT (operator directive: east-west stays measured-only;
the MCP lane must not widen it):

* DEFAULT / ``KUBETEE_MCP_VERIFY=certifi`` -> public web PKI only
  (``certifi.where()``, the bundle *inside the measured image* — no OS trust
  store, no unmeasured bytes; same helper the serving path uses).
* ``KUBETEE_MCP_VERIFY=system`` -> the guest OS trust store (explicit opt-in
  only — this one CAN pull unmeasured platform state).
* ``KUBETEE_MCP_VERIFY=<path>`` -> an explicit CA bundle.
* ``KUBETEE_MCP_VERIFY=eastwest`` -> explicit opt-in composite: the measured
  east-west CA + certifi, for deployments that serve BOTH private
  (east-west-anchored) and public MCP upstreams from one lane. Not the default
  — it makes the MCP lane trust the east-west anchor, blurring the boundary.

The east-west client certificate (``sitecustomize.py``) is still installed for
the serving lane only. Do NOT let it ride on public MCP calls: that hands the
east-west identity to any arbitrary upstream, so the hook keys the attach
strictly on ``cafile == /run/kubetee-eastwest/ca.pem``, which the contexts built
here never carry. Serving, east-west and MCP trust are now three distinct
contexts instead of one shared global.

Activated by the usual ``CustomLogger`` registration (a no-op logger whose
constructor installs the patch at callback-import time — the same pattern as
``kubetee_pricing``).
"""

from __future__ import annotations

import os
import ssl
from typing import Final

from litellm.integrations.custom_logger import CustomLogger

#: Scope for the built context. Populated with the resolved source path(s) so
#: post-apply tests can assert *what* is trusted without a TLS handshake.
TRUST_CONTEXT_DESCR: dict[str, str] = {}

MODE_CERTIFI: Final = "certifi"
MODE_SYSTEM: Final = "system"
MODE_EASTWEST: Final = "eastwest"

_EASTWEST_CA: Final = os.path.join(
    os.environ.get("KUBETEE_EASTWEST_DIR", "/run/kubetee-eastwest"), "ca.pem"
)

_PATCH_MARK: Final = "__kubetee_mcp_trust__"


def _certifi_ca() -> str:
    """The web-PKI bundle shipped *inside the measured image*.

    Imported lazily so the module stays importable without certifi; the image
    always has it (``litellm`` depends on it and ``http_handler`` already calls
    ``certifi.where()`` for the serving path).
    """
    import certifi

    return certifi.where()


def build_mcp_trust_context(source: str | None = None) -> ssl.SSLContext:
    """Build the verification context for the MCP lane.

    ``source`` overrides ``KUBETEE_MCP_VERIFY`` (used by tests). An explicit
    ``SSLContext`` is never built here — that stays the caller's business
    (``get_ssl_configuration`` passes its own through, and this patch does not
    touch it).
    """
    mode: Final = (source or os.environ.get("KUBETEE_MCP_VERIFY", MODE_CERTIFI)).strip() or MODE_CERTIFI
    TRUST_CONTEXT_DESCR.clear()

    if mode == MODE_SYSTEM:
        TRUST_CONTEXT_DESCR["mode"] = MODE_SYSTEM
        return ssl.create_default_context()

    if mode == MODE_CERTIFI:
        ca = _certifi_ca()
        TRUST_CONTEXT_DESCR["mode"] = MODE_CERTIFI
        TRUST_CONTEXT_DESCR["cafile"] = ca
        return ssl.create_default_context(cafile=ca)

    if mode != MODE_EASTWEST:
        # Explicit CA bundle path.
        ca = os.path.expanduser(mode)
        if not os.path.isfile(ca):
            # Fail closed: an unreadable trust anchor must never degrade to
            # "trust whatever the platform hands us".
            raise FileNotFoundError(
                f"KUBETEE_MCP_VERIFY={mode!r} is neither a known mode "
                f"({MODE_CERTIFI!r}, {MODE_SYSTEM!r}, {MODE_EASTWEST!r}) nor a readable CA bundle"
            )
        TRUST_CONTEXT_DESCR["mode"] = "file"
        TRUST_CONTEXT_DESCR["cafile"] = ca
        return ssl.create_default_context(cafile=ca)

    # eastwest (explicit opt-in only): the measured anchor PLUS certifi, for
    # deployments that put private (east-west-anchored) and public MCP
    # upstreams on one lane. Default is certifi — the lanes stay disjoint.
    TRUST_CONTEXT_DESCR["mode"] = MODE_EASTWEST
    ctx = ssl.create_default_context()
    if os.path.isfile(_EASTWEST_CA):
        ctx.load_verify_locations(cafile=_EASTWEST_CA)
        TRUST_CONTEXT_DESCR["cafile"] = _EASTWEST_CA
    TRUST_CONTEXT_DESCR["certifi"] = _certifi_ca()
    ctx.load_verify_locations(cafile=_certifi_ca())
    return ctx


def apply_mcp_trust() -> bool:
    """Default the outbound MCP client's ``ssl_verify`` to its own trust context.

    Patches ``MCPClient.__init__`` (the single construction seam — the proxy
    manager builds every client through it and never passes ``ssl_verify``), so
    the transport factory's ``get_ssl_configuration(self.ssl_verify)`` returns
    this context and no longer inherits the east-west-only global.

    A caller that *does* pass ``ssl_verify`` keeps it: per-server trust stays
    an operator override.

    Returns True when the patch landed, False when the MCP client module is
    not importable (base image without the MCP extra — nothing to do).
    """
    try:
        from litellm.experimental_mcp_client import client as mcp_client_mod
    except Exception:  # ImportError in the image, typing breakage, …
        return False

    original = mcp_client_mod.MCPClient.__init__
    if getattr(original, _PATCH_MARK, False):
        return True

    def patched_init(self: object, *args: object, **kwargs: object) -> None:
        if kwargs.get("ssl_verify") is None:
            kwargs["ssl_verify"] = build_mcp_trust_context()
        original(self, *args, **kwargs)

    setattr(patched_init, _PATCH_MARK, True)
    setattr(patched_init, "__wrapped__", original)
    mcp_client_mod.MCPClient.__init__ = patched_init  # type: ignore[method-assign]
    return True


class KubeTEEMCPTrust(CustomLogger):
    """No-op logger; applying the patch at import/registration is the feature."""

    def __init__(self) -> None:
        super().__init__()
        apply_mcp_trust()


kubetee_mcp_trust_logger = KubeTEEMCPTrust()
