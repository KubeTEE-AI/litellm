"""CI gate: every ``X-KubeTEE-*`` header value must be latin-1 safe.

HTTP header values are latin-1 (PEP 3333 / ASGI). A single non-latin-1 byte in
a value raises ``UnicodeEncodeError`` while the response headers freeze and
turns a healthy completion into a **500**. This gate pins two things so a
measured release cannot ship a regression:

  * ``_latin1_headers`` coerces free-form values to latin-1 (ASCII preserved,
    unmappable bytes replaced with ``?``) — a crash guard, never an evidence
    decision (digests / quotes / signatures / nonces are already ASCII).
  * the **graceful fallback** path (backend evidence unavailable -> ``boot-time``
    boundary label) emits only latin-1-encodable values. This is the exact path
    that 500'd live on a cold evidence-cache miss before the fix: the old
    ``"backend evidence unavailable — boundary label only"`` carried a U+2014
    em-dash at byte 29.

Network-free; no cluster, no Trustee. The standalone runners live beside the
overlay in ``tools/kubetee-litellm-overlay/tests/``; this file pins the same
gate in the pytest suite CI collects.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path
from typing import Any, Final

import pytest

_OVERLAY_DIR: Final = (
    Path(__file__).resolve().parents[4] / "tools" / "kubetee-litellm-overlay"
)


def _ensure_litellm() -> None:
    try:  # pragma: no cover - trivial import probe
        import litellm.integrations.custom_logger  # noqa: F401

        return
    except Exception:
        pass

    litellm_mod = types.ModuleType("litellm")
    integrations = types.ModuleType("litellm.integrations")
    custom_logger = types.ModuleType("litellm.integrations.custom_logger")

    class CustomLogger:  # noqa: D401 - stub base class
        pass

    custom_logger.CustomLogger = CustomLogger
    logging_mod = types.ModuleType("litellm._logging")

    class _L:
        def error(self, *a: Any, **k: Any) -> None:
            pass

        def info(self, *a: Any, **k: Any) -> None:
            pass

    logging_mod.verbose_proxy_logger = _L()
    sys.modules["litellm"] = litellm_mod
    sys.modules["litellm.integrations"] = integrations
    sys.modules["litellm.integrations.custom_logger"] = custom_logger
    sys.modules["litellm._logging"] = logging_mod


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _OVERLAY_DIR / f"{name}.py")
    assert spec is not None and spec.loader is not None, f"cannot load {name}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_ensure_litellm()
sys.path.insert(0, str(_OVERLAY_DIR))  # intra-overlay imports (kubetee_binding, ...)
ka: Final = _load("kubetee_attestation")


def _assert_latin1(headers: dict[str, str]) -> None:
    """Every key and value must encode as latin-1 (the ASGI header contract)."""
    for k, v in headers.items():
        k.encode("latin-1")  # raises UnicodeEncodeError on a bad header NAME
        v.encode("latin-1")  # raises UnicodeEncodeError on a bad header VALUE


# ---------------------------------------------------------------------------
# _latin1_headers sanitizer
# ---------------------------------------------------------------------------


def test_latin1_passthrough_ascii() -> None:
    out = ka._latin1_headers({"X-KubeTEE-Nonce": "deadbeef" * 8})
    assert out == {"X-KubeTEE-Nonce": "deadbeef" * 8}
    _assert_latin1(out)


def test_latin1_replaces_non_latin1_value() -> None:
    # The exact live bug: a U+2014 em-dash in a header value.
    out = ka._latin1_headers({"X-KubeTEE-Backend-Evidence-Error": "unavailable \u2014 x"})
    _assert_latin1(out)
    val = out["X-KubeTEE-Backend-Evidence-Error"]
    assert "\u2014" not in val  # em-dash must be gone
    assert val == "unavailable ? x"  # replaced with '?'


def test_latin1_coerces_non_str_values() -> None:
    out = ka._latin1_headers({"X-KubeTEE-Count": 7})  # type: ignore[dict-item]
    _assert_latin1(out)
    assert out["X-KubeTEE-Count"] == "7"


# ---------------------------------------------------------------------------
# Graceful fallback path emits latin-1 only (the 500 regression)
# ---------------------------------------------------------------------------


def test_fallback_headers_are_latin1(monkeypatch: pytest.MonkeyPatch) -> None:
    """Backend evidence unavailable -> boot-time label, NEVER a 500.

    Forces ``_backend_evidence`` to return ``None`` (the cold-miss / fetch-fail
    state) with an ``api_base`` present, then asserts the returned headers are
    fully latin-1-encodable. Before the fix this path embedded a U+2014 in
    ``X-KubeTEE-Backend-Evidence-Error`` and crashed the response.
    """
    import asyncio

    async def _no_evidence(_url: str) -> None:
        return None

    async def _no_observe(_url: str, _entry: Any) -> None:
        return None

    def _no_guard(_url: str) -> dict[str, str] | None:  # breaker_guard is SYNC
        return None

    monkeypatch.setattr(ka, "_backend_evidence", _no_evidence)
    monkeypatch.setattr(ka, "_observe_backend_evidence", _no_observe)
    monkeypatch.setattr(ka, "breaker_guard", _no_guard)

    headers = asyncio.run(
        ka._backend_identity_headers(
            {"model": "xiaomi/mimo-v2.6-pro"},
            {"api_base": "https://mimo-v2-6-pro.na-us-dallas-132.inference.kubetee.ai/v1"},
        )
    )

    _assert_latin1(headers)  # the core regression assertion
    assert headers["X-KubeTEE-Backend-Attested"] == "boot-time (Trustee EAR; east-west mTLS)"
    assert any(k.lower().endswith("evidence-error") for k in headers)
