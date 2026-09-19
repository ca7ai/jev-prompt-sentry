"""Pure decision function: answers in, verdict out.

No I/O, no clock, no logging. The benchmark replays recorded answers through
this at varying thresholds with zero API calls, which requires purity.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from jev_prompt_sentry.config import Thresholds
from jev_prompt_sentry.guard import GuardOutcome, GuardResult


class Decision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class Verdict:
    decision: Decision
    reasons: tuple[str, ...]
    guard_manipulation_flagged: bool


def decide(result: GuardResult, thresholds: Thresholds) -> Verdict:
    """Block when any single signal crosses its bar. The comparison differs per
    signal and the exact operator is pinned by tests:

    - `is_jailbreak` blocks on `> jailbreak_block` (strictly greater: a score
      exactly equal to the bar allows)
    - `is_indirect_injection` blocks on `> injection_block`
    - `data_exfil_risk` blocks on `>= exfil_block_level` (at the level, not past
      it: 3.0 blocks, because the levels are ordered categories and landing on
      level 3 already means "reveal context AND place it somewhere")
    """
    if result.outcome is GuardOutcome.UNAVAILABLE:
        # The caller decides what to do with this; it is never an allow here.
        return Verdict(Decision.UNAVAILABLE, (), False)
    if result.outcome is GuardOutcome.SKIPPED:
        return Verdict(Decision.ALLOW, (), False)

    manipulation = result.is_guard_manipulation or 0.0
    flagged = manipulation > thresholds.guard_manipulation_flag

    # Manipulation flagged means the other answers are themselves under attack,
    # so trust them less. Nouls only: a 0.10 penalty means nothing on 0-4.
    penalty = thresholds.guard_manipulation_penalty if flagged else 0.0
    jailbreak_bar = thresholds.jailbreak_block - penalty
    injection_bar = thresholds.injection_block - penalty

    reasons: list[str] = []
    if (result.is_jailbreak or 0.0) > jailbreak_bar:
        reasons.append(f"is_jailbreak={result.is_jailbreak:.2f}>{jailbreak_bar:.2f}")
    if (result.is_indirect_injection or 0.0) > injection_bar:
        reasons.append(
            f"is_indirect_injection={result.is_indirect_injection:.2f}>{injection_bar:.2f}"
        )
    if (result.data_exfil_risk or 0.0) >= thresholds.exfil_block_level:
        reasons.append(
            f"data_exfil_risk={result.data_exfil_risk:.2f}>={thresholds.exfil_block_level:.2f}"
        )

    # OR, not a weighted sum: averaging lets one confident signal be diluted by
    # three quiet ones, which is the wrong failure direction for a firewall.
    decision = Decision.BLOCK if reasons else Decision.ALLOW
    return Verdict(decision, tuple(reasons), flagged)
