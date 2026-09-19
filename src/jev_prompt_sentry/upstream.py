"""Passthrough to the upstream Messages API.

Jev Prompt Sentry holds no Anthropic key. The caller's credential header is forwarded
untouched, which keeps the proxy transparent and adds no new secret to store.
TYPESAFE_API_KEY is never forwarded here.
"""

from __future__ import annotations

from collections.abc import Mapping

import httpx
from starlette.background import BackgroundTask
from starlette.responses import Response, StreamingResponse

from jev_prompt_sentry.config import Settings

# Allowlist, not a denylist: a new client header cannot leak upstream by
# default, and hop-by-hop headers (host, content-length, connection) must not
# be copied onto a different connection.
FORWARDED_REQUEST_HEADERS = frozenset(
    {
        "x-api-key",
        "authorization",
        "anthropic-version",
        "anthropic-beta",
        "anthropic-dangerous-direct-browser-access",
        "content-type",
        "accept",
    }
)

# Headers httpx recomputes for the response we build; copying them corrupts it.
_SKIPPED_RESPONSE_HEADERS = frozenset(
    {"content-length", "transfer-encoding", "connection", "content-encoding"}
)

def filter_request_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {
        key.lower(): value
        for key, value in headers.items()
        if key.lower() in FORWARDED_REQUEST_HEADERS
    }

def _response_headers(
    upstream: httpx.Response, extra: Mapping[str, str] | None
) -> dict[str, str]:
    out = {
        key: value
        for key, value in upstream.headers.items()
        if key.lower() not in _SKIPPED_RESPONSE_HEADERS
    }
    out.update(extra or {})
    return out

async def forward(
    client: httpx.AsyncClient,
    settings: Settings,
    body: bytes,
    headers: Mapping[str, str],
    stream: bool,
    extra_response_headers: Mapping[str, str] | None = None,
) -> Response:
    url = f"{settings.upstream_base_url.rstrip('/')}/v1/messages"
    request = client.build_request(
        "POST",
        url,
        content=body,  # verbatim: the guard never rewrites the request
        headers=filter_request_headers(headers),
        timeout=settings.upstream_timeout_s,
    )

    if not stream:
        upstream = await client.send(request)
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers=_response_headers(upstream, extra_response_headers),
        )

    # The guard already resolved, so streaming is a plain pipe: no buffering
    # and no added per-token latency on allowed traffic.
    upstream = await client.send(request, stream=True)
    return StreamingResponse(
        # aiter_bytes, not aiter_raw: httpx solicits `accept-encoding: gzip` on
        # the upstream request and _SKIPPED_RESPONSE_HEADERS drops
        # `content-encoding`, so raw bytes would reach the client as
        # undecodable gzip mislabelled as text/event-stream. aiter_bytes
        # content-decodes, which matches the stripped header and the
        # non-streaming path's use of `.content`.
        upstream.aiter_bytes(),
        status_code=upstream.status_code,
        headers=_response_headers(upstream, extra_response_headers),
        background=BackgroundTask(upstream.aclose),
    )
