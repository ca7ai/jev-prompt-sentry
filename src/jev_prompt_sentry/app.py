"""FastAPI wiring: extract, guard, decide, then forward or reject."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, Request
from starlette.responses import JSONResponse, Response
from typesafe_sdk import AsyncTypeSafeClient

from jev_prompt_sentry.config import Settings, get_settings
from jev_prompt_sentry.errors import anthropic_error
from jev_prompt_sentry.extract import extract
from jev_prompt_sentry.guard import Guard, GuardOutcome
from jev_prompt_sentry.logging import log_request, prompt_digest
from jev_prompt_sentry.policy import Decision, decide
from jev_prompt_sentry.upstream import forward


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # One client each, reused across requests: a cold TLS handshake costs
        # more than the entire guard budget.
        # Ruling R6: Only construct TypeSafe client if guard is not already injected by test.
        if app.state.guard is None:
            async with (
                AsyncTypeSafeClient(timeout=resolved.guard_timeout_ms / 1000) as ts_client,
                httpx.AsyncClient() as http_client,
            ):
                app.state.guard = Guard(ts_client, resolved)
                app.state.http = http_client
                yield
        else:
            # Test has injected guard; only create HTTP client
            async with httpx.AsyncClient() as http_client:
                app.state.http = http_client
                yield

    app = FastAPI(title="Jev Prompt Sentry", version="0.1.0", lifespan=lifespan)
    app.state.guard = None
    app.state.http = None

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        # Liveness only: no Jev call, so orchestrator probes do not burn quota
        # against the 1200 req/min ceiling.
        return JSONResponse({"status": "ok", "model": resolved.model})

    @app.post("/v1/messages")
    async def messages(request: Request) -> Response:
        raw = await request.body()
        try:
            body: Any = json.loads(raw)
        except json.JSONDecodeError:
            return anthropic_error(400, "invalid_request_error", "body is not valid JSON")
        if not isinstance(body, dict):
            return anthropic_error(400, "invalid_request_error", "body must be a JSON object")

        extracted = extract(body)
        result = await request.app.state.guard.evaluate(extracted)
        verdict = decide(result, resolved.thresholds())

        record: dict[str, Any] = {
            "event": "guard",
            "outcome": result.outcome.value,
            "decision": verdict.decision.value,
            "reasons": list(verdict.reasons),
            "guard_manipulation_flagged": verdict.guard_manipulation_flagged,
            "is_jailbreak": result.is_jailbreak,
            "is_indirect_injection": result.is_indirect_injection,
            "data_exfil_risk": result.data_exfil_risk,
            "is_guard_manipulation": result.is_guard_manipulation,
            "guard_ms": round(result.latency_ms, 1),
            "jev_model": result.model,
            "input_tokens": result.input_tokens,
            "skipped_non_text_blocks": extracted.skipped_non_text,
            "skipped_unknown_text_blocks": extracted.skipped_unknown_text,
            "error": result.error,
        }
        if resolved.log_prompts:
            record["user_message"] = extracted.user_message
        else:
            record["user_message_digest"] = prompt_digest(extracted.user_message)

        record["unscreened"] = False  # Flipped to True on fail-open path below

        if verdict.decision is Decision.BLOCK:
            log_request(record)
            # Fixed, non-informative message. Naming the signal and the bar it
            # crossed ("is_jailbreak=0.99>0.85") hands an attacker per-attempt
            # gradient feedback for binary-searching a payload to just under the
            # boundary, and under a manipulation flag it also discloses the
            # penalised bar. The full reason list stays in the log line above.
            return anthropic_error(
                403,
                "jev_prompt_sentry_blocked",
                "Request rejected by Jev Prompt Sentry.",
            )

        unscreened = False
        if verdict.decision is Decision.UNAVAILABLE:
            if not resolved.fail_open:
                log_request(record)
                return anthropic_error(
                    503,
                    "jev_prompt_sentry_guard_unavailable",
                    "Jev Prompt Sentry could not screen this request and is configured to fail closed.",
                )
            unscreened = True
            record["unscreened"] = True

        log_request(record)

        extra = {"X-Jev-Prompt-Sentry-Guard-Ms": f"{result.latency_ms:.1f}"}
        if unscreened:
            extra["X-Jev-Prompt-Sentry-Unscreened"] = "true"
        elif result.outcome is GuardOutcome.SKIPPED:
            # Forwarded, but nothing was screened: there was no text to judge.
            # Stamping "allow" here would let a caller read an unscreened
            # forward as a screened one.
            extra["X-Jev-Prompt-Sentry-Verdict"] = "skipped"
        else:
            extra["X-Jev-Prompt-Sentry-Verdict"] = "allow"

        return await forward(
            request.app.state.http,
            resolved,
            body=raw,
            headers=request.headers,
            stream=bool(body.get("stream")),
            extra_response_headers=extra,
        )

    return app


app = create_app()
