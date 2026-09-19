import httpx
import respx

from jev_prompt_sentry.app import create_app
from jev_prompt_sentry.config import Settings
from jev_prompt_sentry.extract import extract
from jev_prompt_sentry.guard import Guard, GuardOutcome, GuardResult

BODY = {"model": "claude-opus-5", "messages": [{"role": "user", "content": "hi"}]}
UPSTREAM = "https://api.anthropic.com/v1/messages"


class StubGuard:
    def __init__(self, result):
        self._result = result
        self.calls = 0

    async def evaluate(self, extracted):
        self.calls += 1
        return self._result


class FakeTypeSafeClient:
    """Records calls to the Jev API for testing empty-input skip.

    The method is named `system_one` because that is the method Guard.evaluate
    actually calls. Named anything else, the call counter counts a method
    nothing invokes and `calls == 0` is vacuously true.
    """
    def __init__(self):
        self.calls = 0

    async def system_one(self, state, questions, **kwargs):
        self.calls += 1
        # Should never be called for empty input
        raise AssertionError("Jev client called for empty input")

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


def allowed():
    return GuardResult(
        outcome=GuardOutcome.ANSWERED,
        is_jailbreak=0.01,
        data_exfil_risk=0.0,
        is_guard_manipulation=0.02,
        model="jev-1.13.0",
        input_tokens=566,
        latency_ms=140.0,
    )


def blocked():
    return GuardResult(
        outcome=GuardOutcome.ANSWERED,
        is_jailbreak=0.99,
        data_exfil_risk=0.1,
        is_guard_manipulation=0.9,
        model="jev-1.13.0",
        input_tokens=564,
        latency_ms=139.0,
    )


def unavailable():
    return GuardResult(outcome=GuardOutcome.UNAVAILABLE, error="TypeSafeAPITimeoutError: x")


def skipped():
    return GuardResult(outcome=GuardOutcome.SKIPPED)


def build(result, **env):
    app = create_app(Settings(_env_file=None, **env))
    app.state.guard = StubGuard(result)
    return app


async def call(app, body=BODY):
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.post("/v1/messages", json=body, headers={"x-api-key": "k"})


@respx.mock
async def test_allowed_request_reaches_upstream():
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={"id": "msg_1"}))
    app = build(allowed())
    response = await call(app)
    assert response.status_code == 200
    assert route.call_count == 1
    assert response.headers["x-jev-prompt-sentry-verdict"] == "allow"
    assert "x-jev-prompt-sentry-guard-ms" in response.headers


@respx.mock
async def test_skipped_guard_is_not_stamped_allow():
    """Traffic is still forwarded, but a caller must never be able to read
    "allow" as "screened" when the guard never looked at anything."""
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={"id": "msg_1"}))
    response = await call(build(skipped()))
    assert response.status_code == 200
    assert route.call_count == 1
    assert response.headers["x-jev-prompt-sentry-verdict"] == "skipped"
    assert "x-jev-prompt-sentry-guard-ms" in response.headers


@respx.mock
async def test_blocked_request_never_touches_upstream(caplog):
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={"id": "msg_1"}))
    with caplog.at_level("INFO", logger="jev_prompt_sentry"):
        response = await call(build(blocked()))
    assert response.status_code == 403
    # The load-bearing assertion of this whole test suite.
    assert route.call_count == 0
    payload = response.json()
    assert payload["type"] == "error"
    assert payload["error"]["type"] == "jev_prompt_sentry_blocked"
    # The body must not be a calibration oracle: no signal name, no score, no
    # threshold. Otherwise every 403 is a gradient step for the attacker.
    message = payload["error"]["message"]
    assert "is_jailbreak" not in message
    assert "0.99" not in message
    assert "0.85" not in message
    # Every log record must have unscreened as a boolean.
    import json
    logged = [json.loads(r.getMessage()) for r in caplog.records]
    assert len(logged) == 1
    assert logged[0]["unscreened"] is False
    # The reasons are not lost, they are just operator-only.
    assert any("is_jailbreak" in reason for reason in logged[0]["reasons"])


@respx.mock
async def test_guard_unavailable_fails_closed_by_default():
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={"id": "m"}))
    response = await call(build(unavailable()))
    assert response.status_code == 503
    assert route.call_count == 0
    assert response.json()["error"]["type"] == "jev_prompt_sentry_guard_unavailable"


@respx.mock
async def test_guard_unavailable_forwards_when_fail_open_is_set(caplog):
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={"id": "m"}))
    with caplog.at_level("WARNING", logger="jev_prompt_sentry"):
        response = await call(build(unavailable(), fail_open=True))
    assert response.status_code == 200
    assert route.call_count == 1
    assert response.headers["x-jev-prompt-sentry-unscreened"] == "true"
    # Fail-open must log unscreened=true at WARN level.
    import json
    logged = [json.loads(r.getMessage()) for r in caplog.records]
    assert len(logged) == 1
    assert logged[0]["unscreened"] is True


@respx.mock
async def test_streaming_request_is_piped():
    respx.post(UPSTREAM).mock(
        return_value=httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=b"event: message_start\ndata: {}\n\n",
        )
    )
    app = build(allowed())
    body = dict(BODY, stream=True)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            async with client.stream("POST", "/v1/messages", json=body) as response:
                chunks = [chunk async for chunk in response.aiter_bytes()]
    assert b"message_start" in b"".join(chunks)


async def test_malformed_json_is_rejected_without_guarding():
    app = build(allowed())
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/v1/messages", content=b"not json", headers={"content-type": "application/json"}
            )
    assert response.status_code == 400
    assert response.json()["error"]["type"] == "invalid_request_error"
    assert app.state.guard.calls == 0


async def test_healthz_makes_no_guard_call():
    app = build(allowed())
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert app.state.guard.calls == 0


@respx.mock
async def test_prompt_text_is_not_logged_by_default(caplog):
    respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={"id": "m"}))
    with caplog.at_level("INFO", logger="jev_prompt_sentry"):
        await call(build(allowed()), body={"messages": [{"role": "user", "content": "secret words"}]})
    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert "secret words" not in logged
    assert "sha256:" in logged


@respx.mock
async def test_prompt_text_is_logged_when_explicitly_enabled(caplog):
    respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={"id": "m"}))
    app = build(allowed(), log_prompts=True)
    with caplog.at_level("INFO", logger="jev_prompt_sentry"):
        await call(app, body={"messages": [{"role": "user", "content": "secret words"}]})
    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert "secret words" in logged


@respx.mock
async def test_empty_input_skips_guard_and_forwards():
    """Empty input (no readable blocks) -> SKIPPED -> forwarded without a Jev
    call, and stamped `skipped` rather than `allow`."""
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={"id": "msg_1"}))

    # Real Guard with a fake client, so the call counter counts the method
    # production code actually calls.
    fake_client = FakeTypeSafeClient()
    guard = Guard(fake_client, Settings(_env_file=None))
    app = create_app(Settings(_env_file=None))
    app.state.guard = guard

    # Empty content array extracts to empty input
    body = {"model": "claude-opus-5", "messages": [{"role": "user", "content": []}]}

    # Assert the outcome directly: a 200 alone would also be produced by a
    # regressed skip whose AttributeError got swallowed into UNAVAILABLE.
    result = await guard.evaluate(extract(body))
    assert result.outcome is GuardOutcome.SKIPPED
    assert fake_client.calls == 0, "Guard must skip Jev API call for empty input"

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/v1/messages", json=body, headers={"x-api-key": "k"})

    assert response.status_code == 200
    assert route.call_count == 1, "Upstream must be called once"
    assert response.headers["x-jev-prompt-sentry-verdict"] == "skipped"
    assert fake_client.calls == 0, "Guard must skip Jev API call for empty input"
