from jev_prompt_sentry.config import Thresholds
from jev_prompt_sentry.guard import GuardOutcome, GuardResult
from jev_prompt_sentry.policy import Decision, decide

# Explicit literals, not Settings(): every assertion below is a statement about
# these exact boundaries, so a .env file or an exported JEV_PROMPT_SENTRY_JAILBREAK_BLOCK
# must not be able to silently redefine what this file is testing. The real
# defaults are asserted once, in test_config.py.
T = Thresholds(
    jailbreak_block=0.85,
    injection_block=0.85,
    exfil_block_level=3.0,
    guard_manipulation_flag=0.70,
    guard_manipulation_penalty=0.10,
)


def answered(jb=0.0, inj=None, exfil=0.0, gm=0.0):
    return GuardResult(
        outcome=GuardOutcome.ANSWERED,
        is_jailbreak=jb,
        is_indirect_injection=inj,
        data_exfil_risk=exfil,
        is_guard_manipulation=gm,
    )


def test_all_signals_low_allows():
    v = decide(answered(jb=0.01, exfil=0.0, gm=0.02), T)
    assert v.decision is Decision.ALLOW
    assert v.reasons == ()


def test_jailbreak_above_threshold_blocks():
    v = decide(answered(jb=0.86), T)
    assert v.decision is Decision.BLOCK
    assert "is_jailbreak" in v.reasons[0]


def test_jailbreak_exactly_at_threshold_does_not_block():
    # Strictly greater than, matching the brief's "confidence > 0.85".
    assert decide(answered(jb=0.85), T).decision is Decision.ALLOW


def test_injection_above_threshold_blocks():
    assert decide(answered(inj=0.97), T).decision is Decision.BLOCK


def test_missing_injection_answer_is_not_triggered():
    # Omitted from the request when there is no untrusted content. Missing and
    # zero are equivalent; missing is never an error.
    assert decide(answered(inj=None), T).decision is Decision.ALLOW


def test_exfil_at_or_above_level_blocks():
    assert decide(answered(exfil=3.0), T).decision is Decision.BLOCK
    assert decide(answered(exfil=2.99), T).decision is Decision.ALLOW


def test_guard_manipulation_alone_does_not_block():
    v = decide(answered(gm=0.99), T)
    assert v.decision is Decision.ALLOW
    assert v.guard_manipulation_flagged is True


def test_guard_manipulation_lowers_the_noul_thresholds():
    # 0.80 clears neither 0.85 threshold on its own, but with manipulation
    # flagged the bar drops to 0.75.
    assert decide(answered(jb=0.80, gm=0.0), T).decision is Decision.ALLOW
    assert decide(answered(jb=0.80, gm=0.99), T).decision is Decision.BLOCK
    assert decide(answered(inj=0.80, gm=0.99), T).decision is Decision.BLOCK


def test_guard_manipulation_does_not_move_the_score_threshold():
    # A 0.10 penalty is meaningless on a 0-4 level scale.
    assert decide(answered(exfil=2.95, gm=0.99), T).decision is Decision.ALLOW


def test_multiple_triggers_are_all_reported():
    v = decide(answered(jb=0.9, inj=0.9, exfil=4.0), T)
    assert v.decision is Decision.BLOCK
    assert len(v.reasons) == 3


def test_unavailable_is_never_allow():
    v = decide(GuardResult(outcome=GuardOutcome.UNAVAILABLE, error="boom"), T)
    assert v.decision is Decision.UNAVAILABLE


def test_skipped_allows():
    assert decide(GuardResult(outcome=GuardOutcome.SKIPPED), T).decision is Decision.ALLOW
