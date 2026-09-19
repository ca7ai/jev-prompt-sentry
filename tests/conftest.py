"""Test isolation from the developer's machine.

`config.py` sets `env_file=".env"` and `jev-prompt-sentry/.env` is a real file on a
developer box, so without this the suite's assertions depend on whatever that
file and the ambient environment happen to contain. A single exported
`JEV_PROMPT_SENTRY_FAIL_OPEN=true` would flip the fail-closed test from green to red, and a
`JEV_PROMPT_SENTRY_JAILBREAK_BLOCK` override would invalidate every threshold boundary
assertion. A firewall's test suite must not be conditional on one machine.

Tests still construct `Settings` with `_env_file=None` where a `.env` sitting in
the CWD must not be read either; this fixture handles the environment half.
"""

from __future__ import annotations

import os

import pytest


def _scrub_jev_prompt_sentry_environment() -> None:
    for key in list(os.environ):
        if key.startswith("JEV_PROMPT_SENTRY_"):
            del os.environ[key]


# At conftest import, i.e. before any test module is collected. `app.py` builds a
# module-level `app = create_app()`, so `Settings()` runs during collection -
# early enough that a per-test fixture cannot help. An exported
# `JEV_PROMPT_SENTRY_FAIL_OPEN=` (empty) makes that import raise a pydantic bool_parsing
# error and takes the whole suite down at collection time.
_scrub_jev_prompt_sentry_environment()


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every JEV_PROMPT_SENTRY_* variable for the duration of each test.

    Autouse and unconditional: a test that wants an override sets it itself with
    monkeypatch, which still works because monkeypatch undoes in LIFO order.
    """
    for key in list(os.environ):
        if key.startswith("JEV_PROMPT_SENTRY_"):
            monkeypatch.delenv(key, raising=False)
