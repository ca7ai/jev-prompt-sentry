"""Anthropic-shaped error envelopes.

Reusing the upstream envelope means existing Anthropic SDK clients raise an
ordinary APIStatusError instead of failing to parse an unfamiliar shape.
"""

from __future__ import annotations

from starlette.responses import JSONResponse


def anthropic_error(status: int, error_type: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"type": "error", "error": {"type": error_type, "message": message}},
    )
