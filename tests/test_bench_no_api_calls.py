"""Verify sweep makes zero API calls."""

import json
from pathlib import Path
from unittest.mock import patch

from bench.run import sweep


def test_sweep_makes_zero_api_calls(tmp_path: Path):
    """sweep must replay offline with no SDK calls."""
    # Create a minimal test answers file
    answers_path = tmp_path / "test-answers.jsonl"
    with answers_path.open("w") as f:
        f.write(
            json.dumps(
                {
                    "id": "test-01",
                    "label": "benign",
                    "category": "benign_plain",
                    "expect_block": False,
                    "outcome": "answered",
                    "is_jailbreak": 0.01,
                    "is_indirect_injection": None,
                    "data_exfil_risk": 0.0,
                    "is_guard_manipulation": 0.0,
                    "latency_ms": 150.0,
                    "input_tokens": 560,
                    "model": "jev-1.13.0",
                    "error": None,
                }
            )
            + "\n"
        )

    # Patch the SDK client so a future regression that introduces a call here
    # is caught by assert_not_called below. No side_effect: sweep never
    # references AsyncTypeSafeClient today, so a side_effect would be dead code
    # that reads as if it were doing the work.
    with patch("bench.run.AsyncTypeSafeClient") as mock_client:
        result = sweep(str(answers_path), grid=False)

    assert result == 0  # sweep completed successfully
    mock_client.assert_not_called()
