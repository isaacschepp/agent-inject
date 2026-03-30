"""Tests for REST adapter using respx to mock httpx."""

from __future__ import annotations

import httpx
import respx

from agent_inject.harness.adapters.rest import RestAdapter
from agent_inject.models import PayloadInstance


class TestSendPayload:
    @respx.mock
    async def test_success(self, sample_payload_instance: PayloadInstance) -> None:
        respx.post("https://agent.test/").mock(return_value=httpx.Response(200, json={"response": "Hello from agent"}))
        adapter = RestAdapter("https://agent.test/")
        result = await adapter.send_payload(sample_payload_instance)
        assert result.raw_output == "Hello from agent"
        assert result.error is None

    @respx.mock
    async def test_with_context(self, sample_payload_instance: PayloadInstance) -> None:
        route = respx.post("https://agent.test/").mock(return_value=httpx.Response(200, json={"response": "ok"}))
        adapter = RestAdapter("https://agent.test/")
        await adapter.send_payload(sample_payload_instance, context={"session_id": "abc"})
        request = route.calls.last.request
        body = request.content.decode()
        assert "session_id" in body

    @respx.mock
    async def test_http_error(self, sample_payload_instance: PayloadInstance) -> None:
        respx.post("https://agent.test/").mock(return_value=httpx.Response(500, text="Internal Server Error"))
        adapter = RestAdapter("https://agent.test/")
        result = await adapter.send_payload(sample_payload_instance)
        assert result.error is not None
        assert result.raw_output == ""

    @respx.mock
    async def test_connection_error(self, sample_payload_instance: PayloadInstance) -> None:
        respx.post("https://agent.test/").mock(side_effect=httpx.ConnectError("refused"))
        adapter = RestAdapter("https://agent.test/")
        result = await adapter.send_payload(sample_payload_instance)
        assert result.error is not None

    @respx.mock
    async def test_custom_fields(self, sample_payload_instance: PayloadInstance) -> None:
        route = respx.post("https://agent.test/").mock(return_value=httpx.Response(200, json={"output": "custom"}))
        adapter = RestAdapter("https://agent.test/", message_field="prompt", response_field="output")
        result = await adapter.send_payload(sample_payload_instance)
        assert result.raw_output == "custom"
        request_body = route.calls.last.request.content.decode()
        assert "prompt" in request_body


class TestHealthCheck:
    @respx.mock
    async def test_up(self) -> None:
        respx.get("https://agent.test").mock(return_value=httpx.Response(200))
        adapter = RestAdapter("https://agent.test")
        assert await adapter.health_check() is True

    @respx.mock
    async def test_server_error(self) -> None:
        respx.get("https://agent.test").mock(return_value=httpx.Response(500))
        adapter = RestAdapter("https://agent.test")
        assert await adapter.health_check() is False

    @respx.mock
    async def test_connection_refused(self) -> None:
        respx.get("https://agent.test").mock(side_effect=httpx.ConnectError("refused"))
        adapter = RestAdapter("https://agent.test")
        assert await adapter.health_check() is False


class TestInit:
    def test_trailing_slash_stripped(self) -> None:
        adapter = RestAdapter("https://agent.test/")
        assert adapter.base_url == "https://agent.test"

    def test_default_fields(self) -> None:
        adapter = RestAdapter("https://agent.test")
        assert adapter.message_field == "message"
        assert adapter.response_field == "response"
        assert adapter.timeout == 30.0
        assert adapter.headers == {}
