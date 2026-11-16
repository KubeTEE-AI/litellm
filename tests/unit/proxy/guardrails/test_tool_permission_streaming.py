import inspect
from collections.abc import AsyncIterator
from contextlib import contextmanager
from typing import Final

import pytest

import litellm
from litellm.proxy._types import UserAPIKeyAuth
from litellm.proxy.guardrails.guardrail_initializers import initialize_tool_permission
from litellm.proxy.utils import ProxyLogging
from litellm.types.guardrails import Guardrail, LitellmParams
from litellm.types.utils import Delta, ModelResponseStream, StreamingChoices


async def _upstream(*chunks: ModelResponseStream) -> AsyncIterator[ModelResponseStream]:
    for chunk in chunks:
        yield chunk


@contextmanager
def _callback_state(cache: dict[str, object]):
    original_cache: Final = ProxyLogging._callback_capabilities_cache
    original_callbacks: Final = litellm.callbacks[:]
    try:
        ProxyLogging._callback_capabilities_cache = cache
        yield
    finally:
        litellm.callbacks[:] = original_callbacks
        ProxyLogging._callback_capabilities_cache = original_cache


async def _collect(stream: AsyncIterator[ModelResponseStream]) -> list[ModelResponseStream]:
    assert inspect.isasyncgen(stream)
    return [chunk async for chunk in stream]


@pytest.mark.asyncio
async def test_default_off_tool_permission_streams_each_chunk_without_buffering() -> None:
    cache: Final[dict[str, object]] = {}
    with _callback_state(cache):
        initialize_tool_permission(
            LitellmParams(guardrail="tool_permission", mode="post_call", default_on=False),
            Guardrail(guardrail_name="test-tool-permission", litellm_params={}),
        )
        chunks: Final = tuple(
            ModelResponseStream(choices=[StreamingChoices(index=0, delta=Delta(content="token"))]) for _ in range(3)
        )
        stream = ProxyLogging(None).async_post_call_streaming_iterator_hook(
            response=_upstream(*chunks),
            user_api_key_dict=UserAPIKeyAuth(),
            request_data={},
        )
        assert await _collect(stream) == list(chunks)
