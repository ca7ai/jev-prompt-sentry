"""Structured request logging.

Prompt text is digested by default. A firewall log is otherwise a collection of
every attack payload alongside every private thing your users typed.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

logger = logging.getLogger("jev_prompt_sentry")


def prompt_digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def log_request(record: dict[str, Any]) -> None:
    level = logging.WARNING if record.get("unscreened") else logging.INFO
    logger.log(level, json.dumps(record, default=str, sort_keys=True))
