# ruff: noqa: T201  -- this is a console report; printing is the point.
"""
False-positive harness for the SAFi gate.

Runs a corpus of benign computer-use tool calls through the gate and counts
how many are refused. A gate that denies everything is not a gate; this is
the measurement that keeps that honest.

The offline layers (1 and 3) are deterministic, so their rate is exact and
needs no API key. Layer 2 is measured only when ANTHROPIC_API_KEY is set,
and is reported as NULL otherwise rather than folded into the headline.

SCOPE
    benign_corpus.json is hand-authored, not captured from production agent
    traffic. A rate measured here is a rate on this corpus. It is a floor,
    not a field measurement, and the corpus is deliberately weighted toward
    calls that sit close to a rule -- so the number it produces should be
    read as pessimistic for ordinary traffic and optimistic for adversarial.

Usage:
    python run_safi_false_positives.py              # offline layers only
    python run_safi_false_positives.py --layer2     # include the judge (costs money)
    python run_safi_false_positives.py --max-rate 2 # fail above 2 percent

Exit code is 0 only if the offline false-positive rate is within --max-rate.
"""

from __future__ import annotations

import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from safi_gate import (
    STATE_ALLOW,
    evaluate_conscience,
    evaluate_layer_1,
    evaluate_layer_3,
)

GREEN, RED, YELLOW, DIM, RESET = (
    "\033[32m", "\033[31m", "\033[31m", "\033[2m", "\033[0m",
)
YELLOW = "\033[33m"

CORPUS = Path(__file__).with_name("benign_corpus.json")


def load_corpus() -> dict[str, Any]:
    with CORPUS.open(encoding="utf-8") as handle:
        return json.load(handle)


def main() -> int:
    include_layer_2 = "--layer2" in sys.argv
    max_rate = 0.0
    for i, arg in enumerate(sys.argv):
        if arg == "--max-rate" and i + 1 < len(sys.argv):
            max_rate = float(sys.argv[i + 1])

    corpus = load_corpus()
    cases = corpus["cases"]
    print(f"{YELLOW}SAFi false-positive harness{RESET}")
    n_cat = len({c["category"] for c in cases})
    print(f"{DIM}corpus: {len(cases)} benign calls, {n_cat} categories{RESET}")
    print(f"{YELLOW}Corpus is hand-authored, not captured traffic. See meta.caveat.{RESET}\n")

    offline_fp: list[tuple[str, str, str, str]] = []
    per_category: defaultdict[str, int] = defaultdict(int)
    per_rule: Counter[str] = Counter()

    for case in cases:
        tool, payload = case["tool"], case["input"]
        v1 = evaluate_layer_1(tool, payload)
        v3 = evaluate_layer_3(tool, payload) if v1.allowed else None
        refused = v1 if not v1.allowed else (v3 if v3 and v3.state != STATE_ALLOW else None)
        if refused is not None:
            desc = payload.get("command") or json.dumps(payload, sort_keys=True)
            rule = f"{refused.layer}/{refused.rule}"
            offline_fp.append((case["id"], case["category"], desc[:70], rule))
            per_category[case["category"]] += 1
            per_rule[f"{refused.layer}/{refused.rule}"] += 1

    total = len(cases)
    rate = 100.0 * len(offline_fp) / total

    print(f"{YELLOW}Offline layers (1 + 3) -- deterministic, no API key needed{RESET}")
    if offline_fp:
        print(f"  {RED}{len(offline_fp)} of {total} benign calls refused ({rate:.1f}%){RESET}\n")
        for cid, cat, desc, rule in offline_fp:
            print(f"  {RED}FP{RESET}  {cid:14} {DIM}{cat:11}{RESET} {desc}")
            print(f"      {DIM}-> {rule}{RESET}")
        print(f"\n  {DIM}by rule:{RESET}")
        for rule, n in per_rule.most_common():
            print(f"    {n:3}  {rule}")
        print(f"  {DIM}by category:{RESET}")
        for cat, n in sorted(per_category.items(), key=lambda kv: -kv[1]):
            of = sum(1 for c in cases if c["category"] == cat)
            print(f"    {n:3}/{of:<3} {cat}")
    else:
        print(f"  {GREEN}0 of {total} benign calls refused (0.0%){RESET}")

    layer2_note = "NULL -- ANTHROPIC_API_KEY not set, judge not measured"
    if include_layer_2:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print(f"\n{RED}--layer2 requested but ANTHROPIC_API_KEY is not set.{RESET}")
            return 1
        print(f"\n{YELLOW}Layer 2 -- live judge (this spends money){RESET}")
        survivors = [c for c in cases if evaluate_layer_1(c["tool"], c["input"]).allowed]
        l2_fp = []
        for case in survivors:
            verdict = evaluate_conscience(case["tool"], case["input"])
            if verdict.state != STATE_ALLOW:
                desc = case["input"].get("command") or json.dumps(case["input"], sort_keys=True)
                l2_fp.append((case["id"], desc[:70], f"{verdict.layer}/{verdict.rule}"))
                print(f"  {RED}FP{RESET}  {case['id']:14} {desc[:70]}")
                print(f"      {DIM}-> {verdict.layer}/{verdict.rule}: {verdict.reason}{RESET}")
        l2_rate = 100.0 * len(l2_fp) / len(survivors) if survivors else 0.0
        layer2_note = f"{len(l2_fp)}/{len(survivors)} refused ({l2_rate:.1f}%)"
        if not l2_fp:
            print(f"  {GREEN}0 of {len(survivors)} refused by the judge{RESET}")

    print(f"\n{YELLOW}Summary{RESET}")
    print(f"  offline false-positive rate : {rate:.1f}%  ({len(offline_fp)}/{total})")
    print(f"  layer 2 false-positive rate : {layer2_note}")
    print(f"  threshold                   : {max_rate:.1f}%")

    if rate > max_rate:
        print(f"\n{RED}Offline rate {rate:.1f}% exceeds the {max_rate:.1f}% threshold.{RESET}")
        return 1
    print(f"\n{GREEN}Within threshold.{RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
