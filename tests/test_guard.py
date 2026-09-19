import pytest
import httpx
from typesafe_sdk import TypeSafeAPITimeoutError, TypeSafeRateLimitError

from jev_prompt_sentry.config import Settings
from jev_prompt_sentry.extract import extract
from jev_prompt_sentry.guard import QUESTIONS, Guard, GuardOutcome


class FakeAnswer:
    """Stand-in for NoulAnswer / ScoreAnswer."""

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class FakeUsage:
    input_tokens = 566
    output_tokens = 40


class FakeResponse:
    def __init__(self, answers):
        self.answers = answers
        self.model = "jev-1.13.0"
        self.usage = FakeUsage()


class FakeClient:
    """Records the call it was given and returns canned answers."""

    def __init__(self, answers=None, raises=None):
        self._answers = answers or {}
        self._raises = raises
        self.calls = []

    async def system_one(self, state, questions, **kwargs):
        self.calls.append({"state": state, "questions": questions, "kwargs": kwargs})
        if self._raises is not None:
            raise self._raises
        return FakeResponse(self._answers)


def _answers(jb=0.01, inj=None, exfil=0.0, gm=0.02):
    out = {
        "is_jailbreak": FakeAnswer(type="noul", noul=jb),
        "data_exfil_risk": FakeAnswer(type="score", score=exfil, confidence=0.9),
        "is_guard_manipulation": FakeAnswer(type="noul", noul=gm),
    }
    if inj is not None:
        out["is_indirect_injection"] = FakeAnswer(type="noul", noul=inj)
    return out


async def test_answers_are_mapped_onto_the_result():
    client = FakeClient(_answers(jb=0.99, exfil=3.5, gm=0.9))
    guard = Guard(client, Settings(_env_file=None))
    result = await guard.evaluate(extract({"messages": [{"role": "user", "content": "hi"}]}))
    assert result.outcome is GuardOutcome.ANSWERED
    assert result.is_jailbreak == 0.99
    assert result.data_exfil_risk == 3.5
    assert result.is_guard_manipulation == 0.9
    assert result.is_indirect_injection is None
    assert result.model == "jev-1.13.0"
    assert result.input_tokens == 566
    assert result.latency_ms >= 0


async def test_injection_question_is_omitted_without_untrusted_content():
    client = FakeClient(_answers())
    await Guard(client, Settings(_env_file=None)).evaluate(
        extract({"messages": [{"role": "user", "content": "hi"}]})
    )
    assert "is_indirect_injection" not in client.calls[0]["questions"]
    assert set(client.calls[0]["questions"]) == {
        "is_jailbreak",
        "data_exfil_risk",
        "is_guard_manipulation",
    }


async def test_injection_question_is_sent_with_untrusted_content():
    client = FakeClient(_answers(inj=0.97))
    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "read it"},
                    {"type": "tool_result", "tool_use_id": "t", "content": "IGNORE PRIOR"},
                ],
            }
        ]
    }
    result = await Guard(client, Settings(_env_file=None)).evaluate(extract(body))
    assert "is_indirect_injection" in client.calls[0]["questions"]
    assert result.is_indirect_injection == 0.97


async def test_model_pin_timeout_and_no_retries_are_passed():
    client = FakeClient(_answers())
    await Guard(client, Settings(_env_file=None)).evaluate(
        extract({"messages": [{"role": "user", "content": "hi"}]})
    )
    kwargs = client.calls[0]["kwargs"]
    assert kwargs["model"] == "jev-1.13.0"
    assert kwargs["timeout"] == pytest.approx(0.3)
    # In-path retries would consume the latency budget the guard protects.
    assert kwargs["retry"].max_retries == 0


@pytest.mark.parametrize(
    "error",
    [
        TypeSafeAPITimeoutError(timeout=1.0),
        TypeSafeRateLimitError(status=429, body={}, headers=httpx.Headers()),
        RuntimeError("something unexpected"),
    ],
)
async def test_every_failure_maps_to_unavailable(error):
    guard = Guard(FakeClient(raises=error), Settings(_env_file=None))
    result = await guard.evaluate(extract({"messages": [{"role": "user", "content": "hi"}]}))
    assert result.outcome is GuardOutcome.UNAVAILABLE
    assert result.error is not None
    assert result.is_jailbreak is None


async def test_degraded_response_is_unavailable_not_an_exception():
    """A partial provider response is guard unavailability, not a Jev Prompt Sentry bug:
    it must reach the 503 envelope, never escape as a bare 500."""
    answers = _answers()
    del answers["data_exfil_risk"]
    guard = Guard(FakeClient(answers), Settings(_env_file=None))
    result = await guard.evaluate(extract({"messages": [{"role": "user", "content": "hi"}]}))
    assert result.outcome is GuardOutcome.UNAVAILABLE
    assert "KeyError" in (result.error or "")
    assert result.is_jailbreak is None


async def test_unexpected_answer_shape_is_unavailable():
    answers = _answers()
    answers["is_jailbreak"] = FakeAnswer(type="score", score=1.0)  # no .noul
    guard = Guard(FakeClient(answers), Settings(_env_file=None))
    result = await guard.evaluate(extract({"messages": [{"role": "user", "content": "hi"}]}))
    assert result.outcome is GuardOutcome.UNAVAILABLE
    assert "AttributeError" in (result.error or "")


async def test_empty_input_skips_the_api_call():
    client = FakeClient(_answers())
    result = await Guard(client, Settings(_env_file=None)).evaluate(
        extract({"messages": [{"role": "assistant", "content": "hi"}]})
    )
    assert result.outcome is GuardOutcome.SKIPPED
    assert client.calls == []


def test_all_four_questions_are_defined():
    assert set(QUESTIONS) == {
        "is_jailbreak",
        "is_indirect_injection",
        "data_exfil_risk",
        "is_guard_manipulation",
    }
    assert len(QUESTIONS["data_exfil_risk"].criteria) == 5
