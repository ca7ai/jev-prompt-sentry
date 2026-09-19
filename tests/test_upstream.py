import gzip

import httpx
import respx

from jev_prompt_sentry.config import Settings
from jev_prompt_sentry.upstream import filter_request_headers, forward

def test_only_allowlisted_headers_are_forwarded():
    got = filter_request_headers(
        {
            "x-api-key": "fake-caller-key-not-a-real-credential",
            "anthropic-version": "2023-06-01",
            "anthropic-beta": "beta-feature",
            "content-type": "application/json",
            "accept": "application/json",
            "host": "localhost:8000",
            "content-length": "123",
            "connection": "keep-alive",
            "x-forwarded-for": "10.0.0.1",
        }
    )
    assert got == {
        "x-api-key": "fake-caller-key-not-a-real-credential",
        "anthropic-version": "2023-06-01",
        "anthropic-beta": "beta-feature",
        "content-type": "application/json",
        "accept": "application/json",
    }

def test_header_matching_is_case_insensitive():
    assert filter_request_headers({"X-Api-Key": "k"}) == {"x-api-key": "k"}

@respx.mock
async def test_non_streaming_forwards_body_verbatim_and_returns_upstream_response():
    route = respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(
            200, json={"id": "msg_1", "content": []}, headers={"x-request-id": "req_1"}
        )
    )
    body = b'{"model":"claude-opus-5","messages":[{"role":"user","content":"hi"}]}'
    async with httpx.AsyncClient() as client:
        response = await forward(
            client,
            Settings(_env_file=None),
            body=body,
            headers={"x-api-key": "k", "content-type": "application/json"},
            stream=False,
            extra_response_headers={"X-Jev-Prompt-Sentry-Verdict": "allow"},
        )
    assert response.status_code == 200
    assert route.calls[0].request.content == body
    assert route.calls[0].request.headers["x-api-key"] == "k"
    assert response.headers["x-jev-prompt-sentry-verdict"] == "allow"
    assert response.headers["x-request-id"] == "req_1"

@respx.mock
async def test_upstream_error_status_is_passed_through_unchanged():
    respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(429, json={"type": "error", "error": {"type": "rate_limit_error"}})
    )
    async with httpx.AsyncClient() as client:
        response = await forward(
            client, Settings(_env_file=None), body=b"{}", headers={}, stream=False
        )
    assert response.status_code == 429

@respx.mock
async def test_streaming_returns_a_streaming_response():
    respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=b"event: message_start\ndata: {}\n\n",
        )
    )
    async with httpx.AsyncClient() as client:
        response = await forward(
            client, Settings(_env_file=None), body=b'{"stream":true}', headers={}, stream=True
        )
        chunks = [chunk async for chunk in response.body_iterator]
    assert b"message_start" in b"".join(chunks)
    assert response.headers["content-type"] == "text/event-stream"

@respx.mock
async def test_gzip_streaming_body_reaches_the_client_decoded():
    """httpx asks upstream for gzip and we strip `content-encoding`, so the
    streamed body must be decoded or the client gets undecodable bytes labelled
    text/event-stream."""
    payload = b"event: message_start\ndata: {}\n\n"
    respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(
            200,
            headers={
                "content-type": "text/event-stream",
                "content-encoding": "gzip",
            },
            content=gzip.compress(payload),
        )
    )
    async with httpx.AsyncClient() as client:
        response = await forward(
            client, Settings(_env_file=None), body=b'{"stream":true}', headers={}, stream=True
        )
        chunks = [chunk async for chunk in response.body_iterator]
    body = b"".join(chunks)
    assert body == payload
    assert not body.startswith(b"\x1f\x8b")
    # The header we strip must stay stripped: the body is no longer encoded.
    assert "content-encoding" not in response.headers
