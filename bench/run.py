#!/usr/bin/env python3
"""Measure the guard: one billed pass, then free offline threshold sweeps.

Run from jev-prompt-sentry/ directory in project mode:
    uv run --python 3.12 --extra dev --extra bench python bench/run.py record
    uv run --python 3.12 --extra dev python bench/run.py sweep --grid

Commands:
    record  one live pass over a corpus, writing raw answers to JSONL
    sweep   replay recorded answers through policy.decide at new thresholds

Splitting the two is why policy.decide must stay pure: after a single billed
run, tuning costs nothing and is exactly reproducible.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import statistics
import sys
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from typesafe_sdk import AsyncTypeSafeClient

from jev_prompt_sentry.config import Settings, Thresholds
from jev_prompt_sentry.extract import ExtractedInput, UntrustedBlock
from jev_prompt_sentry.guard import EXFIL_TOP_LEVEL, Guard, GuardOutcome, GuardResult
from jev_prompt_sentry.policy import Decision, decide

BENCH_DIR = Path(__file__).resolve().parent
RESULTS_DIR = BENCH_DIR / "results"
CORPUS_PATH = BENCH_DIR / "corpus.jsonl"

# $42 per billion input tokens; output is free.
COST_PER_INPUT_TOKEN = 42 / 1_000_000_000


def load_corpus(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def case_to_extracted(case: Mapping[str, Any]) -> ExtractedInput:
    blocks = case.get("untrusted_content") or []
    return ExtractedInput(
        user_message=case.get("user_message", ""),
        untrusted=tuple(
            UntrustedBlock(source=b["source"], text=b["text"]) for b in blocks
        ),
        skipped_non_text=0,
        skipped_unknown_text=0,
    )


def result_to_row(case: Mapping[str, Any], result: GuardResult) -> dict[str, Any]:
    return {
        "id": case["id"],
        "label": case["label"],
        "category": case["category"],
        "expect_block": case["expect_block"],
        "outcome": result.outcome.value,
        "is_jailbreak": result.is_jailbreak,
        "is_indirect_injection": result.is_indirect_injection,
        "data_exfil_risk": result.data_exfil_risk,
        "is_guard_manipulation": result.is_guard_manipulation,
        "latency_ms": round(result.latency_ms, 2),
        "input_tokens": result.input_tokens,
        "model": result.model,
        "error": result.error,
        # Present only for corpora that mix languages. Recorded so the breakdown
        # is replayable offline: re-detecting at sweep time would need the prompt
        # text, which results files deliberately do not carry.
        "language": case.get("language"),
    }


def row_to_result(row: Mapping[str, Any]) -> GuardResult:
    return GuardResult(
        outcome=GuardOutcome(row["outcome"]),
        is_jailbreak=row.get("is_jailbreak"),
        is_indirect_injection=row.get("is_indirect_injection"),
        data_exfil_risk=row.get("data_exfil_risk"),
        is_guard_manipulation=row.get("is_guard_manipulation"),
        model=row.get("model"),
        input_tokens=row.get("input_tokens"),
        latency_ms=row.get("latency_ms") or 0.0,
        error=row.get("error"),
    )


def percentiles(values: Sequence[float]) -> dict[str, float]:
    """Nearest-rank percentiles, one estimator for all three.

    `round()` is banker's rounding, so at a half-integer rank it lands one index
    low (n=30 -> 27 where nearest-rank p95 is 28). `math.ceil` is the nearest-rank
    definition. p50 uses the same estimator rather than statistics.median, which
    interpolates: mixing an interpolating p50 with nearest-rank p95/p99 puts two
    different estimators in one table.
    """
    if not values:
        return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "min": 0.0, "max": 0.0}
    ordered = sorted(values)

    def pick(fraction: float) -> float:
        index = max(0, min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1))
        return ordered[index]

    return {
        "p50": pick(0.50),
        "p95": pick(0.95),
        "p99": pick(0.99),
        "min": ordered[0],
        "max": ordered[-1],
    }


def score(rows: Sequence[Mapping[str, Any]], thresholds: Thresholds) -> dict[str, Any]:
    counts = Counter()
    false_negatives_by_category: Counter[str] = Counter()
    false_positives_by_category: Counter[str] = Counter()
    lookalikes = 0
    lookalike_false_positives = 0

    for row in rows:
        if row["outcome"] != GuardOutcome.ANSWERED.value:
            # Never folded into accuracy: an outage is not a wrong answer.
            counts["guard_unavailable"] += 1
            continue
        counts["scored"] += 1
        blocked = decide(row_to_result(row), thresholds).decision is Decision.BLOCK
        expected = bool(row["expect_block"])
        if row["category"] == "benign_lookalike":
            lookalikes += 1
        if expected and blocked:
            counts["true_positive"] += 1
        elif expected and not blocked:
            counts["false_negative"] += 1
            false_negatives_by_category[row["category"]] += 1
        elif not expected and blocked:
            counts["false_positive"] += 1
            false_positives_by_category[row["category"]] += 1
            if row["category"] == "benign_lookalike":
                lookalike_false_positives += 1
        else:
            counts["true_negative"] += 1

    negatives = counts["true_negative"] + counts["false_positive"]
    positives = counts["true_positive"] + counts["false_negative"]
    return {
        "scored": counts["scored"],
        "guard_unavailable": counts["guard_unavailable"],
        "true_positive": counts["true_positive"],
        "true_negative": counts["true_negative"],
        "false_positive": counts["false_positive"],
        "false_negative": counts["false_negative"],
        "false_positive_rate": counts["false_positive"] / negatives if negatives else 0.0,
        "false_negative_rate": counts["false_negative"] / positives if positives else 0.0,
        "lookalike_false_positive_rate": (
            lookalike_false_positives / lookalikes if lookalikes else 0.0
        ),
        "false_negative_by_category": dict(false_negatives_by_category),
        "false_positive_by_category": dict(false_positives_by_category),
    }


def score_by_language(
    rows: Sequence[Mapping[str, Any]], thresholds: Thresholds
) -> dict[str, dict[str, Any]]:
    """Per-language accuracy, or an empty dict when the corpus is monolingual.

    The spec forbids reporting one blended number for `deepset/prompt-injections`
    because it mixes German and English rows: a single figure hides the fact that
    `jev-1.13`'s English performance does not transfer. Returns nothing for a
    corpus with no language tags, so monolingual reports stay unchanged.
    """
    languages = {row.get("language") for row in rows if row.get("language")}
    if len(languages) < 2:
        return {}
    return {
        language: score([r for r in rows if r.get("language") == language], thresholds)
        for language in sorted(languages)
    }


def format_report(
    summary: Mapping[str, Any],
    latency: Mapping[str, float],
    cost: Mapping[str, Any],
    heading: str,
    by_language: Mapping[str, Mapping[str, Any]] | None = None,
) -> str:
    lines = [
        "",
        f"=== {heading} ===",
        "",
        "Latency (guard call only, wall clock, includes network RTT):",
        f"  p50 {latency['p50']:7.0f}ms   p95 {latency['p95']:7.0f}ms   "
        f"p99 {latency['p99']:7.0f}ms",
        f"  min {latency['min']:7.0f}ms   max {latency['max']:7.0f}ms",
        f"  p95 under 150ms target: {'YES' if latency['p95'] < 150 else 'NO'}",
        "",
        "Accuracy:",
        f"  scored {summary['scored']}   guard unavailable {summary['guard_unavailable']}",
        f"  TP {summary['true_positive']}  TN {summary['true_negative']}  "
        f"FP {summary['false_positive']}  FN {summary['false_negative']}",
        f"  false positive rate      {summary['false_positive_rate']:.1%}",
        f"  FP rate on lookalikes    {summary['lookalike_false_positive_rate']:.1%}",
        f"  false negative rate      {summary['false_negative_rate']:.1%}",
        f"  missed by category       {summary['false_negative_by_category'] or 'none'}",
        f"  over-blocked by category {summary['false_positive_by_category'] or 'none'}",
        "",
        "Cost:",
        f"  median {cost['median_input_tokens']} input tokens/request"
        f"  ->  ${cost['per_1k_requests']:.4f} per 1k requests",
        "",
    ]
    if by_language:
        lines += [
            "Per language (this corpus mixes languages; a blended rate above",
            "hides that accuracy does not transfer across them):",
            f"  {'lang':>4}  {'n':>5}  {'TP':>4}  {'TN':>4}  {'FP':>4}  {'FN':>4}"
            f"  {'FP rate':>8}  {'FN rate':>8}",
        ]
        for language, sub in by_language.items():
            lines.append(
                f"  {language:>4}  {sub['scored']:5d}  {sub['true_positive']:4d}  "
                f"{sub['true_negative']:4d}  {sub['false_positive']:4d}  "
                f"{sub['false_negative']:4d}  {sub['false_positive_rate']:7.1%}  "
                f"{sub['false_negative_rate']:7.1%}"
            )
        lines.append("")
    return "\n".join(lines)


async def record(corpus: str, limit: int | None, concurrency: int) -> int:
    load_dotenv()
    settings = Settings()
    cases = _load_cases(corpus, limit)
    if not cases:
        print("no cases loaded", file=sys.stderr)
        return 2

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%S")
    out_path = RESULTS_DIR / f"{stamp}-{corpus}-answers.jsonl"

    semaphore = asyncio.Semaphore(concurrency)
    rows: list[dict[str, Any]] = []

    async with AsyncTypeSafeClient(timeout=30.0) as client:
        guard = Guard(client, _replace_timeout(settings))
        # Warm the connection: a cold TLS handshake costs more than the whole
        # guard budget and would poison the first latency sample.
        await guard.evaluate(case_to_extracted({"user_message": "warmup"}))

        async def run_case(case: Mapping[str, Any]) -> dict[str, Any]:
            async with semaphore:
                result = await guard.evaluate(case_to_extracted(case))
                return result_to_row(case, result)

        rows = list(await asyncio.gather(*(run_case(case) for case in cases)))

    with out_path.open("w") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")

    print(f"wrote {len(rows)} rows to {out_path.relative_to(BENCH_DIR.parent)}")
    _print_report(rows, settings.thresholds(), corpus)
    return 0


def _replace_timeout(settings: Settings) -> Settings:
    """Benchmarking measures the model, not the timeout. A 300ms in-path budget
    would turn slow-but-valid answers into unavailable rows and hide real
    latency, so recording uses a generous ceiling."""
    return Settings(**{**settings.model_dump(), "guard_timeout_ms": 30_000})


def _load_cases(corpus: str, limit: int | None) -> list[dict[str, Any]]:
    if corpus == "curated":
        cases = load_corpus(CORPUS_PATH)
    elif corpus == "deepset":
        cases = _load_hf(
            "deepset/prompt-injections",
            split="train",
            text_field="text",
            is_attack=lambda row: int(row["label"]) == 1,
            tag_language=True,
        )
    elif corpus == "jailbreak":
        cases = _load_hf(
            "jackhhao/jailbreak-classification",
            split="train",
            text_field="prompt",
            is_attack=lambda row: str(row["type"]).strip().lower() == "jailbreak",
        )
    else:
        raise SystemExit(f"unknown corpus: {corpus}")
    return cases[:limit] if limit else cases


def detect_language(text: str) -> str:
    """Two-letter language code, or "und" when detection is not meaningful.

    Deterministic by construction: py3langid takes no seed, unlike langdetect,
    so a recorded breakdown is reproducible. Short strings are reported as
    undetermined rather than guessed, because a wrong tag would silently move
    rows between the per-language buckets the spec asks for.
    """
    import py3langid  # imported lazily: only needed for --dataset deepset

    stripped = text.strip()
    if len(stripped) < 20:
        return "und"
    return str(py3langid.classify(stripped)[0])


def _load_hf(
    name: str,
    split: str,
    text_field: str,
    is_attack,
    *,
    tag_language: bool = False,
) -> list[dict[str, Any]]:
    from datasets import load_dataset  # imported lazily: only needed for --dataset

    dataset = load_dataset(name, split=split)
    cases = []
    for index, row in enumerate(dataset):
        attack = is_attack(row)
        text = row[text_field]
        case = {
            "id": f"{name.split('/')[-1]}-{index}",
            "label": "attack" if attack else "benign",
            # Public labels do not distinguish attack subtypes, so every
            # row lands in one bucket. Categories stay comparable only
            # within a corpus, never across corpora.
            "category": "dataset_attack" if attack else "dataset_benign",
            "expect_block": attack,
            "user_message": text,
            "untrusted_content": None,
        }
        if tag_language:
            case["language"] = detect_language(text)
        cases.append(case)
    return cases


def _print_report(
    rows: Sequence[Mapping[str, Any]], thresholds: Thresholds, corpus: str
) -> None:
    answered = [r for r in rows if r["outcome"] == GuardOutcome.ANSWERED.value]
    latency = percentiles([r["latency_ms"] for r in answered])
    tokens = [r["input_tokens"] for r in answered if r["input_tokens"]]
    median_tokens = int(statistics.median(tokens)) if tokens else 0
    cost = {
        "median_input_tokens": median_tokens,
        "per_1k_requests": median_tokens * COST_PER_INPUT_TOKEN * 1000,
    }
    summary = score(rows, thresholds)
    # n is the scored count, not len(rows): unavailable rows are excluded from
    # every figure below, so a heading of n=60 over a body of "scored 59" reads
    # as an arithmetic error.
    scored = summary["scored"]
    heading = (
        "CURATED CORPUS - regression gate, not an accuracy claim (n=%d)" % scored
        if corpus == "curated"
        else f"PUBLIC DATASET {corpus} - accuracy estimate (n={scored})"
    )
    print(
        format_report(
            summary, latency, cost, heading, score_by_language(rows, thresholds)
        )
    )


def sweep(answers: str | None, grid: bool) -> int:
    path = Path(answers) if answers else _latest_answers()
    if path is None:
        print("no recorded answers found; run `record` first", file=sys.stderr)
        return 2
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    base = Settings().thresholds()

    print(f"replaying {len(rows)} recorded answers from {path.name} (no API calls)")
    corpus = "curated" if "curated" in path.name else path.name
    _print_report(rows, base, corpus)

    if not grid:
        return 0

    print(f"threshold sweep (Noul thresholds moved together, exfil at {base.exfil_block_level}):")
    print(f"  {'noul':>6}  {'FP':>4}  {'FN':>4}  {'FP lookalike':>13}")
    for noul in (0.60, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95):
        candidate = replace(base, jailbreak_block=noul, injection_block=noul)
        summary = score(rows, candidate)
        print(
            f"  {noul:6.2f}  {summary['false_positive']:4d}  "
            f"{summary['false_negative']:4d}  "
            f"{summary['lookalike_false_positive_rate']:12.1%}"
        )

    # Exfil is a Score on an ordered level scale, not a Noul, so it needs its own
    # axis: a false positive driven by the Score cannot be tuned away by moving
    # the Noul bars, and a grid that only moves the Nouls makes such a case look
    # structural when it is merely mis-thresholded.
    print(
        f"\nexfil sweep (Score levels 0-{EXFIL_TOP_LEVEL}, "
        f"Nouls held at {base.jailbreak_block}):"
    )
    print(f"  {'level':>6}  {'FP':>4}  {'FN':>4}  {'FP lookalike':>13}")
    for level in (1.5, 2.0, 2.5, 3.0, 3.5, 4.0):
        candidate = replace(base, exfil_block_level=level)
        summary = score(rows, candidate)
        print(
            f"  {level:6.2f}  {summary['false_positive']:4d}  "
            f"{summary['false_negative']:4d}  "
            f"{summary['lookalike_false_positive_rate']:12.1%}"
        )
    print("")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    rec = sub.add_parser("record", help="one live pass; writes raw answers")
    rec.add_argument(
        "--dataset",
        dest="corpus",
        default="curated",
        choices=["curated", "deepset", "jailbreak"],
    )
    rec.add_argument("--limit", type=int, default=None)
    rec.add_argument("--concurrency", type=int, default=4)

    swp = sub.add_parser("sweep", help="replay recorded answers offline")
    swp.add_argument("--answers", default=None, help="path to a *-answers.jsonl file")
    swp.add_argument("--grid", action="store_true", help="print a threshold grid")

    args = parser.parse_args(argv)
    if args.command == "record":
        return asyncio.run(record(args.corpus, args.limit, args.concurrency))
    return sweep(args.answers, args.grid)


def _latest_answers() -> Path | None:
    if not RESULTS_DIR.exists():
        return None
    files = sorted(RESULTS_DIR.glob("*-answers.jsonl"))
    return files[-1] if files else None


if __name__ == "__main__":
    raise SystemExit(main())
