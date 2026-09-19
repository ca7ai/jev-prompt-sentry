import dataclasses

import pytest

from jev_prompt_sentry.config import Settings, get_settings


def test_defaults_match_the_spec():
    # _env_file=None plus the autouse environment fixture in conftest.py: this is
    # the one test whose whole purpose is asserting the shipped defaults, so
    # neither a developer's .env nor an exported JEV_PROMPT_SENTRY_* may change the answer.
    s = Settings(_env_file=None)
    assert s.model == "jev-1.13.0"
    assert s.guard_timeout_ms == 300
    assert s.fail_open is False
    assert s.log_prompts is False
    assert s.upstream_base_url == "https://api.anthropic.com"
    assert s.upstream_timeout_s == 600.0
    t = s.thresholds()
    # Calibrated 2026-09-19, not from the brief: see the note in config.py.
    assert t.jailbreak_block == 0.80
    assert t.injection_block == 0.80
    assert t.exfil_block_level == 3.0
    assert t.guard_manipulation_flag == 0.70
    assert t.guard_manipulation_penalty == 0.10


def test_env_overrides_use_the_jev_prompt_sentry_prefix(monkeypatch):
    monkeypatch.setenv("JEV_PROMPT_SENTRY_FAIL_OPEN", "true")
    monkeypatch.setenv("JEV_PROMPT_SENTRY_JAILBREAK_BLOCK", "0.6")
    monkeypatch.setenv("JEV_PROMPT_SENTRY_GUARD_TIMEOUT_MS", "120")
    s = Settings(_env_file=None)
    assert s.fail_open is True
    assert s.thresholds().jailbreak_block == 0.6
    assert s.guard_timeout_ms == 120


def test_thresholds_are_frozen():
    t = Settings(_env_file=None).thresholds()
    with pytest.raises(dataclasses.FrozenInstanceError):
        t.jailbreak_block = 0.1  # type: ignore[misc]


def test_get_settings_is_cached():
    assert get_settings() is get_settings()
