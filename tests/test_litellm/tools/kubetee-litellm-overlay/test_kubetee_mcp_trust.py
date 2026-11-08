"""Trust-scope tests for kubetee_mcp_trust (the MCP-client trust fix).

The property under test: the MCP lane's trust context is *built by measured
code* and is scoped — it must never silently widen to the platform trust store
and must never depend on unmeasured OS state. These assertions are on the
resolved source paths (TRUST_CONTEXT_DESCR) plus the resulting SSLContext's
verification posture.

Loaded from the overlay path like the binding tests: no package install, the
file is the artifact (it ships COPY'd into site-packages).
"""

from __future__ import annotations

import importlib.util
import ssl
import sys
from pathlib import Path
from typing import Final

import certifi
import pytest

_MODULE_PATH: Final = (
    Path(__file__).resolve().parents[4]
    / "tools"
    / "kubetee-litellm-overlay"
    / "kubetee_mcp_trust.py"
)
_SPEC: Final = importlib.util.spec_from_file_location("kubetee_mcp_trust", _MODULE_PATH)
assert _SPEC is not None and _SPEC.loader is not None, f"cannot load {_MODULE_PATH}"
mt: Final = importlib.util.module_from_spec(_SPEC)
sys.modules["kubetee_mcp_trust"] = mt
_SPEC.loader.exec_module(mt)


def test_certifi_mode_uses_the_measured_web_pki_bundle() -> None:
    ctx: Final = mt.build_mcp_trust_context(source="certifi")
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname
    assert mt.TRUST_CONTEXT_DESCR == {
        "mode": "certifi",
        "cafile": certifi.where(),
    }


def test_system_mode_is_explicit_and_still_verifies() -> None:
    ctx: Final = mt.build_mcp_trust_context(source="system")
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert mt.TRUST_CONTEXT_DESCR == {"mode": "system"}


def test_default_mode_is_certifi_only_no_eastwest_anchor() -> None:
    # Operator directive (2026-10-28): the lanes stay DISJOINT — the MCP lane
    # must not widen the measured-only east-west trust. Default = web PKI.
    ctx: Final = mt.build_mcp_trust_context()
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert mt.TRUST_CONTEXT_DESCR == {"mode": "certifi", "cafile": certifi.where()}
    assert mt.TRUST_CONTEXT_DESCR["cafile"] != mt._EASTWEST_CA


def test_eastwest_composite_is_opt_in_only() -> None:
    ctx: Final = mt.build_mcp_trust_context(source="eastwest")
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert mt.TRUST_CONTEXT_DESCR.get("certifi") == certifi.where()


def test_explicit_ca_bundle_path_is_honored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mt, "_EASTWEST_CA", "/nonexistent/kubetee-eastwest/ca.pem")
    ctx: Final = mt.build_mcp_trust_context(source=certifi.where())
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert mt.TRUST_CONTEXT_DESCR == {"mode": "file", "cafile": certifi.where()}


def test_unreadable_anchor_fails_closed() -> None:
    with pytest.raises(FileNotFoundError):
        mt.build_mcp_trust_context(source="/nonexistent/kubetee-ca.pem")


def test_eastwest_anchor_loads_when_present(monkeypatch: pytest.MonkeyPatch) -> None:
    # Stand-in anchor: any parseable PEM bundle. Presence (not identity) is
    # what this asserts — the real anchor is fetched in-guest by
    # kubetee_eastwest before LiteLLM starts.
    monkeypatch.setattr(mt, "_EASTWEST_CA", certifi.where())
    mt.build_mcp_trust_context(source="eastwest")
    assert mt.TRUST_CONTEXT_DESCR == {
        "mode": "eastwest",
        "cafile": certifi.where(),
        "certifi": certifi.where(),
    }


def test_eastwest_mode_degrades_only_the_private_half(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No anchor in the image -> public trust still works, nothing platform-wide
    # is pulled in, and no exception escapes to the request path.
    monkeypatch.setattr(mt, "_EASTWEST_CA", "/nonexistent/kubetee-eastwest/ca.pem")
    ctx: Final = mt.build_mcp_trust_context(source="eastwest")
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert mt.TRUST_CONTEXT_DESCR == {
        "mode": "eastwest",
        "certifi": certifi.where(),
    }


def test_contexts_are_fresh_per_call() -> None:
    # The east-west client-cert attach (sitecustomize) keys on a shared
    # context identity; the MCP lane must not hand out a context that carries
    # (or later receives) the east-west client identity.
    first: Final = mt.build_mcp_trust_context(source="certifi")
    second: Final = mt.build_mcp_trust_context(source="certifi")
    assert first is not second
