# ruff: noqa: T201  -- this is a console report; printing is the point.
"""
Latency and cost harness for the SAFi gate.

Answers the first question an operator asks: what does putting this in front
of every tool call cost, in milliseconds and in dollars.

The offline layers are measured exactly and need no API key. Layer 2 is a
network round trip, so its latency and token usage are measured only with
ANTHROPIC_API_KEY set; without one they are reported NULL rather than
estimated, because a made-up millisecond figure is worse than no figure.

What the offline run CAN establish without a key:
  - Layer 1 and Layer 3 latency distributions, which bound the gate's
    unavoidable overhead
  - the share of realistic traffic that reaches the paid layer at all,
    which is what actually drives the bill
  - the request's fixed token floor, and whether prompt caching can help

Usage:
    python run_safi_latency.py                 # offline only
    python run_safi_latency.py --layer2 [N]    # time N live judge calls
"""

from __future__ import annotations

import json
import os
import statistics
import sys
import time
from pathlib import Path
from typing import Any

from safi_gate import (
    JUDGE_SYSTEM_PROMPT,
    JUDGE_USER_TEMPLATE,
    SAFI_JUDGE_MAX_TOKENS,
    SAFI_JUDGE_MODEL,
    STATE_ALLOW,
    evaluate_conscience,
    evaluate_layer_1,
    evaluate_layer_3,
    flatten_payload,
)

GREEN, RED, YELLOW, DIM, RESET = (
    "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m",
)

# Claude Haiku 4.5 list pricing, USD per million tokens.
PRICE_IN_PER_MTOK = 1.00
PRICE_OUT_PER_MTOK = 5.00
# Minimum cacheable prefix for Haiku 4.5. A cache_control marker on a shorter
# prefix does not error -- it silently does nothing.
CACHE_MIN_TOKENS = 4096


def percentiles(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    def pct(p: float) -> float:
        idx = min(len(ordered) - 1, round(p / 100.0 * (len(ordered) - 1)))
        return ordered[idx]
    return {
        "min": ordered[0], "p50": pct(50), "p95": pct(95),
        "p99": pct(99), "max": ordered[-1], "mean": statistics.fmean(ordered),
    }


def time_layer(fn: Any, cases: list[dict[str, Any]], reps: int) -> list[float]:
    samples = []
    for _ in range(reps):
        for case in cases:
            start = time.perf_counter()
            fn(case["tool"], case["input"])
            samples.append((time.perf_counter() - start) * 1_000_000)  # microseconds
    return samples


def main() -> int:
    corpus_path = Path(__file__).with_name("benign_corpus.json")
    with corpus_path.open(encoding="utf-8") as handle:
        cases = json.load(handle)["cases"]

    print(f"{YELLOW}SAFi latency and cost harness{RESET}")
    print(f"{DIM}corpus: {len(cases)} realistic tool calls{RESET}\n")

    # -- offline layers ----------------------------------------------------
    reps = 20
    print(f"{YELLOW}Offline layers -- {len(cases)} calls x {reps} reps, microseconds{RESET}")
    rows = []
    for name, fn in (("Layer 1 (regex)", evaluate_layer_1), ("Layer 3 (SAIVAS)", evaluate_layer_3)):
        stats = percentiles(time_layer(fn, cases, reps))
        rows.append((name, stats))
        print(
            f"  {name:18} p50 {stats['p50']:8.1f}  p95 {stats['p95']:8.1f}  "
            f"p99 {stats['p99']:8.1f}  max {stats['max']:9.1f}"
        )
    combined_p95 = sum(s["p95"] for _, s in rows)
    print(
        f"  {DIM}combined p95 ~ {combined_p95:.0f} us = {combined_p95/1000:.3f} ms "
        f"per call, before any network{RESET}"
    )

    # -- how much traffic reaches the paid layer ---------------------------
    reaching = 0
    for case in cases:
        if not evaluate_layer_1(case["tool"], case["input"]).allowed:
            continue
        if evaluate_layer_3(case["tool"], case["input"]).state != STATE_ALLOW:
            continue
        reaching += 1
    share = 100.0 * reaching / len(cases)
    print(f"\n{YELLOW}Share of traffic reaching Layer 2{RESET}")
    print(f"  {reaching}/{len(cases)} = {share:.1f}% of benign calls pay for a judge round trip")
    print(
        f"  {DIM}The offline screens are nearly free; the bill is set by this "
        f"share. On benign\n  traffic almost nothing is filtered out before "
        f"the paid layer, which is the cost\n  profile to plan for.{RESET}"
    )

    # -- fixed request size ------------------------------------------------
    payloads = [len(flatten_payload(c["input"])) for c in cases]
    fixed_chars = len(JUDGE_SYSTEM_PROMPT) + len(JUDGE_USER_TEMPLATE)
    print(f"\n{YELLOW}Request size{RESET}")
    print(f"  fixed prompt (system + template) : {fixed_chars:,} characters")
    print(f"  payload p50 / p95 / max          : "
          f"{sorted(payloads)[len(payloads)//2]} / "
          f"{sorted(payloads)[int(len(payloads)*0.95)]} / {max(payloads)} characters")
    print(f"  max_tokens ceiling per verdict    : {SAFI_JUDGE_MAX_TOKENS}")

    print(f"\n{YELLOW}Prompt caching{RESET}")
    print(
        f"  The judge system prompt is identical on every call, so caching is "
        f"the obvious\n  lever. It is not available here: {SAFI_JUDGE_MODEL} "
        f"requires a {CACHE_MIN_TOKENS}-token minimum\n  cacheable prefix, and "
        f"{fixed_chars:,} characters is far below that. A cache_control "
        f"marker\n  on a shorter prefix does not error -- it silently does "
        f"nothing and reports\n  cache_creation_input_tokens: 0. Caching would "
        f"require either a larger fixed\n  prompt or a model tier with a lower "
        f"minimum."
    )
    return report_layer_2(cases)


def report_layer_2(cases: list[dict[str, Any]]) -> int:
    print(f"\n{YELLOW}Layer 2 -- live judge{RESET}")
    if "--layer2" not in sys.argv:
        print(f"  {DIM}not measured (pass --layer2 to time real calls; it spends money){RESET}")
        print(f"  latency  : {YELLOW}NULL{RESET}")
        print(f"  cost/call: {YELLOW}NULL{RESET}")
        print(
            f"\n{YELLOW}STATUS: NULL for Layer 2 latency and cost. Reason: not "
            f"measured in this run.{RESET}\n"
            f"{DIM}Every figure above is from this machine and this corpus; "
            f"none of it is an estimate.{RESET}"
        )
        return 0

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print(f"  {RED}--layer2 requires ANTHROPIC_API_KEY.{RESET}")
        return 1

    n = 20
    for i, arg in enumerate(sys.argv):
        if arg == "--layer2" and i + 1 < len(sys.argv) and sys.argv[i + 1].isdigit():
            n = int(sys.argv[i + 1])

    sample = [c for c in cases if evaluate_layer_1(c["tool"], c["input"]).allowed][:n]
    print(f"  {DIM}timing {len(sample)} real judge calls against {SAFI_JUDGE_MODEL}{RESET}")

    latencies: list[float] = []
    refused = 0
    for case in sample:
        start = time.perf_counter()
        verdict = evaluate_conscience(case["tool"], case["input"])
        latencies.append((time.perf_counter() - start) * 1000)  # milliseconds
        if verdict.state != STATE_ALLOW:
            refused += 1

    stats = percentiles(latencies)
    print(
        f"  latency ms   p50 {stats['p50']:7.0f}  p95 {stats['p95']:7.0f}  "
        f"p99 {stats['p99']:7.0f}  max {stats['max']:7.0f}"
    )
    print(f"  refused      {refused}/{len(sample)} of these benign calls")
    print(
        f"\n  {DIM}Token usage is not captured here -- evaluate_conscience "
        f"returns a Verdict, not\n  the raw response, so usage counts are not "
        f"exposed. Cost per call at "
        f"${PRICE_IN_PER_MTOK:.2f}/MTok in\n  and ${PRICE_OUT_PER_MTOK:.2f}"
        f"/MTok out cannot be computed from this run.{RESET}"
    )
    print(f"\n{YELLOW}STATUS: NULL for cost per call. Reason: token usage not instrumented.{RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
