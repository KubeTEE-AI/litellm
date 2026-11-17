"""Retired-video backend protection against the current upstream callback contracts."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

module_path = Path(__file__).resolve().parents[4] / "tools/kubetee-litellm-overlay/kubetee_route_guard.py"
spec = importlib.util.spec_from_file_location("kubetee_route_guard", module_path)
assert spec and spec.loader
route_guard = importlib.util.module_from_spec(spec)
sys.modules["kubetee_route_guard"] = route_guard
spec.loader.exec_module(route_guard)


def hook(data: dict | None = None, call_type: str = "avideo_generation") -> None:
    asyncio.run(route_guard.kubetee_route_guard_logger.async_pre_call_hook(None, None, data or {}, call_type))


@pytest.mark.parametrize("call_type", ["avideo_status", "avideo_content"])
def test_unresolvable_video_id_fails_closed_without_backend(call_type: str) -> None:
    with pytest.raises(HTTPException) as error:
        hook({"video_id": "unresolvable-test-id"}, call_type)
    assert error.value.status_code == 404


def test_video_enumeration_is_blocked():
    with pytest.raises(HTTPException) as error:
        hook(call_type="avideo_list")
    assert error.value.status_code == 404


def test_well_formed_video_id_lacks_any_backend_contact():
    from litellm.types.videos.utils import encode_video_id_with_provider

    video_id = encode_video_id_with_provider(
        video_id="test", provider="hosted_vllm",
        model_id="00000000-0000-0000-0000-000000000000",
    )
    assert route_guard._video_id_is_resolvable(video_id)
    hook({"video_id": video_id}, "avideo_status")


def test_non_video_callbacks_are_not_intercepted():
    hook({"model": "test"}, "acompletion")


@pytest.mark.parametrize(
    "model",
    ["native-openai/kimi-k3.1-pro-redpill", "native-openai/kimi-k3-redpill"],
)
def test_public_chat_call_to_redpill_kimi_backup_is_rejected_for_every_key(model: str):
    """Without this guard, an admin key must also remain non-routable directly."""
    with pytest.raises(HTTPException) as error:
        hook({"model": model}, "acompletion")
    assert error.value.status_code == 403


def test_public_streaming_call_to_redpill_kimi_backup_is_rejected():
    with pytest.raises(HTTPException) as error:
        hook({"model": "native-openai/kimi-k3.1-pro-redpill", "stream": True}, "acompletion")
    assert error.value.status_code == 403


def test_public_kimi_primary_and_other_redpill_models_are_unchanged():
    hook({"model": "moonshotai/kimi-k3.1-pro"}, "acompletion")
    hook({"model": "native-openai-glm-5-3-redpill"}, "acompletion")
