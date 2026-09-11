# ruff: noqa: T201  -- this is a console report; printing is the point.
"""
SAIVAS conformance suite for SAFi Layer 3.

Checks SAFi's Humility screen against the reference implementation --
Uniformedi/humility-guardrail -- by running BOTH and comparing verdicts on
the same inputs. The reference is imported and executed, not transcribed,
so this cannot drift from what the reference actually does.

WHAT THIS PROVES
    SAFi Layer 3 agrees with the reference implementation of the six
    Humility rules: same rules, same severity split, same pattern tables,
    same trigger conditions, same obligations -- and that each documented
    divergence is present and is the divergence the docs claim.

WHAT THIS DOES NOT PROVE
    That either implementation conforms to the SAIVAS standard as published
    in *Uniform Gnosis, Volume I*. That document is not an input to this
    suite. The reference implementation is the only authority consulted
    here, so a rule the reference gets wrong is a rule this suite will
    happily confirm SAFi also gets wrong. Conformance to the reference is
    not conformance to the standard.

    Confirming the published standard requires reading it against both
    implementations -- a human review, not a test run.

Sections:
    A. Rule inventory        all six rules present, identically named
    B. Severity split        which rules deny, which abstain
    C. Pattern tables        byte-identical phrase lists
    D. Differential: text    same payload -> same rule fires, both sides
    E. Differential: flags   all 72 context combinations, both sides
    F. Obligations           audit.log always, attestation iff restricted
    G. Declared divergences  the documented differences are real

Usage:
    pip install git+https://github.com/Uniformedi/humility-guardrail@main
    python run_saivas_conformance.py

Exit code is 0 only if every check passed.
"""

from __future__ import annotations

import itertools
from typing import Any

from safi_gate import (
    AUTHORITY_PATTERNS,
    LAYER_3,
    METAPHYSICAL_PATTERNS,
    PERSUASION_PATTERNS,
    SAIVAS_ABSTAIN,
    SAIVAS_HARD_DENY,
    STATE_ABSTAIN,
    STATE_ALLOW,
    STATE_DENY,
    evaluate_layer_3,
    normalize,
)

GREEN, RED, YELLOW, DIM, RESET = (
    "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m",
)


class Results:
    def __init__(self) -> None:
        self.passed = 0
        self.failed: list[str] = []

    def record(self, ok: bool, label: str, detail: str = "") -> None:
        if ok:
            self.passed += 1
            suffix = f"\n        {DIM}{detail}{RESET}" if detail else ""
            print(f"  {GREEN}PASS{RESET}  {label}{suffix}")
        else:
            self.failed.append(label)
            suffix = f"\n        {DIM}{detail}{RESET}" if detail else ""
            print(f"  {RED}FAIL{RESET}  {label}{suffix}")


def load_reference() -> Any:
    """Import the reference implementation, or None if it is not installed."""
    try:
        import humility.rules as ref
    except Exception:  # noqa: BLE001 -- any import failure means unavailable
        return None
    return ref


def ref_rules_fired(ref: Any, text: str, **flags: Any) -> list[str]:
    """Rule ids the reference fires, in the order it reports them."""
    decision = ref.evaluate([{"role": "user", "content": text}], **flags)
    out = []
    for reason in decision.deny_reasons:
        rule_id = reason.split(":")[0].strip()
        if rule_id not in out:
            out.append(rule_id)
    return out


def safi_rule_fired(text: str, **flags: Any) -> tuple[str | None, str, str]:
    """(rule id, category, state) SAFi returns for the same input."""
    verdict = evaluate_layer_3("bash", {"command": text}, **flags)
    if verdict.state == STATE_ALLOW:
        return None, "", STATE_ALLOW
    rule_id = verdict.reason.split(":")[0].strip()
    return rule_id, verdict.rule, verdict.state


# ---------------------------------------------------------------------------
# A. Rule inventory
# ---------------------------------------------------------------------------
def section_a(results: Results, ref: Any) -> None:
    print(f"\n{YELLOW}A. Rule inventory{RESET}")
    safi_rules = set(SAIVAS_HARD_DENY) | set(SAIVAS_ABSTAIN)
    ref_rules = set(ref.HARD_DENY_REASONS) | set(ref.REFRAMABLE_REASONS)

    results.record(
        len(safi_rules) == 6, "SAFi implements exactly six Humility rules",
        f"{sorted(safi_rules)}",
    )
    results.record(
        safi_rules == ref_rules, "rule ids identical to the reference",
        f"SAFi-only: {sorted(safi_rules - ref_rules) or 'none'}; "
        f"reference-only: {sorted(ref_rules - safi_rules) or 'none'}",
    )
    for n in range(1, 7):
        rule_id = f"Humility {n}"
        results.record(rule_id in safi_rules, f"{rule_id} is implemented")


# ---------------------------------------------------------------------------
# B. Severity split
# ---------------------------------------------------------------------------
def section_b(results: Results, ref: Any) -> None:
    print(f"\n{YELLOW}B. Severity split (deny vs abstain){RESET}")
    results.record(
        dict(SAIVAS_HARD_DENY) == dict(ref.HARD_DENY_REASONS),
        "hard-deny rules and categories match the reference",
        f"SAFi {dict(SAIVAS_HARD_DENY)}",
    )
    results.record(
        dict(SAIVAS_ABSTAIN) == dict(ref.REFRAMABLE_REASONS),
        "abstaining rules and categories match the reference's reframable set",
        f"SAFi {dict(SAIVAS_ABSTAIN)}",
    )
    results.record(
        not (set(SAIVAS_HARD_DENY) & set(SAIVAS_ABSTAIN)),
        "no rule is both hard-deny and abstaining",
    )


# ---------------------------------------------------------------------------
# C. Pattern tables
# ---------------------------------------------------------------------------
def section_c(results: Results, ref: Any) -> None:
    print(f"\n{YELLOW}C. Pattern tables{RESET}")
    for name, mine, theirs in (
        ("H1 metaphysical", METAPHYSICAL_PATTERNS, ref.METAPHYSICAL_PATTERNS),
        ("H3 authority", AUTHORITY_PATTERNS, ref.AUTHORITY_PATTERNS),
        ("H5 persuasion", PERSUASION_PATTERNS, ref.PERSUASION_PATTERNS),
    ):
        results.record(
            tuple(mine) == tuple(theirs), f"{name} phrase list is identical",
            f"{len(mine)} phrases; diff: {set(mine) ^ set(theirs) or 'none'}",
        )


# ---------------------------------------------------------------------------
# D. Differential on payload text
# ---------------------------------------------------------------------------
def section_d(results: Results, ref: Any) -> None:
    print(f"\n{YELLOW}D. Differential -- same text, both implementations{RESET}")
    corpus: list[tuple[str, str]] = []
    for phrase in METAPHYSICAL_PATTERNS:
        corpus.append((f"echo '{phrase}' > note.md", "Humility 1"))
    for phrase in AUTHORITY_PATTERNS:
        corpus.append((f"echo '{phrase}' > note.md", "Humility 3"))
    for phrase in PERSUASION_PATTERNS:
        corpus.append((f"echo '{phrase}' > note.md", "Humility 5"))
    benign = [
        "ls -la /var/log",
        "grep -rn TODO src/",
        "pip install requests",
        "what is the cosmological constant",
    ]

    agreed = 0
    for text, expected in corpus:
        mine_rule, _, mine_state = safi_rule_fired(text)
        theirs = ref_rules_fired(ref, text)
        ok = mine_rule == expected and expected in theirs and mine_state == STATE_DENY
        if ok:
            agreed += 1
        else:
            results.record(
                False, f"disagreement on {expected} payload",
                f"text={text!r} SAFi={mine_rule}/{mine_state} reference={theirs}",
            )
    results.record(
        agreed == len(corpus),
        f"all {len(corpus)} pattern payloads classified identically",
        f"{agreed}/{len(corpus)} agreed",
    )

    clean = 0
    for text in benign:
        mine_rule, _, mine_state = safi_rule_fired(text)
        theirs = ref_rules_fired(ref, text)
        if mine_rule is None and not theirs and mine_state == STATE_ALLOW:
            clean += 1
        else:
            results.record(
                False, "false positive on benign text",
                f"text={text!r} SAFi={mine_rule} reference={theirs}",
            )
    results.record(
        clean == len(benign),
        f"all {len(benign)} benign payloads allowed by both",
    )


# ---------------------------------------------------------------------------
# E. Differential on context flags -- the full 72-combination truth table
# ---------------------------------------------------------------------------
FLAG_SPACE = {
    "request_type": ("standard", "high_impact", "prediction"),
    "data_classification": ("public", "internal", "restricted"),
    "uncertainty_declared": (True, False),
    "has_human_consensus": (True, False),
    "within_validated_domain": (True, False),
}


def section_e(results: Results, ref: Any) -> None:
    print(f"\n{YELLOW}E. Differential -- context flags, all combinations{RESET}")
    names = list(FLAG_SPACE)
    combos = list(itertools.product(*(FLAG_SPACE[n] for n in names)))
    neutral = "ls -la /var/log"  # no pattern fires, so only flags decide

    disagreements: list[str] = []
    abstained = 0
    for values in combos:
        flags = dict(zip(names, values, strict=True))
        mine_rule, _, mine_state = safi_rule_fired(neutral, **flags)
        theirs = [r for r in ref_rules_fired(ref, neutral, **flags) if r in SAIVAS_ABSTAIN]

        # SAFi returns the first firing rule; the reference reports all of
        # them, in the same H2 -> H4 -> H6 order. Compare like with like.
        expected = theirs[0] if theirs else None
        if mine_rule != expected:
            disagreements.append(f"{flags} SAFi={mine_rule} reference={theirs}")
        if expected is not None:
            abstained += 1
            if mine_state != STATE_ABSTAIN:
                disagreements.append(f"{flags} fired {mine_rule} as {mine_state}, expected abstain")
        elif mine_state != STATE_ALLOW:
            disagreements.append(f"{flags} allowed by reference, SAFi returned {mine_state}")

    results.record(
        not disagreements,
        f"all {len(combos)} flag combinations agree with the reference",
        f"{abstained} of {len(combos)} abstain; "
        + (f"first disagreement: {disagreements[0]}" if disagreements else "no disagreements"),
    )
    for d in disagreements[:5]:
        results.record(False, "flag-combination disagreement", d)


# ---------------------------------------------------------------------------
# F. Obligations
# ---------------------------------------------------------------------------
def section_f(results: Results, ref: Any) -> None:
    print(f"\n{YELLOW}F. Obligations{RESET}")
    for classification in ("public", "internal", "restricted"):
        verdict = evaluate_layer_3(
            "bash", {"command": "ls -la /var/log"},
            data_classification=classification, has_human_consensus=True,
        )
        decision = ref.evaluate(
            [{"role": "user", "content": "ls -la /var/log"}],
            data_classification=classification, has_human_consensus=True,
        )
        mine = sorted(o["type"] for o in verdict.obligations)
        theirs = sorted(o["type"] for o in decision.obligations)
        results.record(
            mine == theirs, f"obligations match for data_classification={classification!r}",
            f"{mine}",
        )


# ---------------------------------------------------------------------------
# G. Declared divergences -- these differences are intentional and documented.
# A test that asserts they EXIST catches someone silently "fixing" one and
# leaving NOTICE and README describing a system that no longer exists.
# ---------------------------------------------------------------------------
def section_g(results: Results, ref: Any) -> None:
    print(f"\n{YELLOW}G. Declared divergences (documented in NOTICE / README){RESET}")

    # 1. Subject matter: SAFi scores tool calls, so a payload nested anywhere
    #    in the structure is screened. The reference scores user messages only.
    nested = evaluate_layer_3(
        "str_replace_editor",
        {"command": "create", "path": "/tmp/x", "file_text": "the universe demands it"},
    )
    results.record(
        nested.state == STATE_DENY and nested.layer == LAYER_3,
        "SAFi screens nested tool payloads, not just a message body",
        f"{nested.rule} on a file_text field",
    )
    assistant_only = ref.evaluate([{"role": "assistant", "content": "the universe demands it"}])
    results.record(
        assistant_only.allow,
        "reference inspects user messages only (documented scope difference)",
        "an assistant-role message is not screened by the reference",
    )

    # 2. Normalisation: this was a divergence and is no longer one. SAFi
    #    folds confusables and strips invisibles; the reference did NFKC +
    #    lowercase only, so a Cyrillic homoglyph walked past it -- until
    #    humility-guardrail 3401842 added the same folding. Asserting parity
    #    here rather than a difference is the point: if either side loses the
    #    fold, the two stop agreeing and this fails.
    cyrillic = "echo 'c\u043esmic truth' > note.md"
    mine_rule, _, _ = safi_rule_fired(cyrillic)
    theirs = ref_rules_fired(ref, cyrillic)
    results.record(
        mine_rule == "Humility 1" and theirs == ["Humility 1"],
        "both fold a Cyrillic homoglyph before matching (parity, not divergence)",
        f"SAFi={mine_rule} reference={theirs or 'allowed'}",
    )
    results.record(
        normalize("c\u043esmic") == "cosmic" and normalize("us\u200bermod") == "usermod",
        "SAFi normalisation folds confusables and strips invisibles",
    )

    # 3. Three-state verdict: the reference exposes has_hard_deny /
    #    has_reframable on a boolean allow; SAFi promotes that to a state.
    abstain = evaluate_layer_3(
        "bash", {"command": "ls"}, request_type="high_impact", uncertainty_declared=False,
    )
    deny = evaluate_layer_3("bash", {"command": "echo 'cosmic truth'"})
    results.record(
        abstain.state == STATE_ABSTAIN and deny.state == STATE_DENY
        and not abstain.allowed and not deny.allowed,
        "SAFi promotes reframable/hard-deny to a first-class verdict state",
        f"abstain={abstain.state} deny={deny.state}, both falsy",
    )
    results.record(
        bool(abstain.guidance) and not deny.guidance,
        "only an abstention carries resolution guidance",
    )


def main() -> int:
    print(f"{YELLOW}SAIVAS conformance -- SAFi Layer 3 vs humility-guardrail{RESET}")
    ref = load_reference()
    if ref is None:
        # Not a skip. Without the reference there is nothing to conform TO,
        # and a suite that passes in that state would be asserting conformance
        # it never checked.
        print(
            f"{RED}The reference implementation is not installed, so nothing "
            f"was compared.{RESET}\n"
            f"{DIM}  pip install git+https://github.com/Uniformedi/"
            f"humility-guardrail@main{RESET}"
        )
        return 1

    print(f"{DIM}Reference: {ref.__file__}{RESET}")
    print(
        f"{YELLOW}Scope: conformance to the reference IMPLEMENTATION. This suite "
        f"does not read\n       *Uniform Gnosis, Volume I* and cannot confirm "
        f"either codebase against\n       the published standard.{RESET}"
    )

    results = Results()
    for section in (section_a, section_b, section_c, section_d, section_e, section_f, section_g):
        section(results, ref)

    total = results.passed + len(results.failed)
    print()
    if results.failed:
        print(f"{RED}{len(results.failed)}/{total} check(s) FAILED:{RESET}")
        for name in results.failed:
            print(f"  - {name}")
        return 1
    print(f"{GREEN}All {total} conformance checks passed.{RESET}")
    print(
        f"{YELLOW}SAFi Layer 3 matches the reference implementation. Conformance "
        f"to the\npublished SAIVAS standard is not established by this run.{RESET}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
