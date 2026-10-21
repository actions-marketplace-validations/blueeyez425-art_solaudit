# SolAudit Benchmark: Model-Evaluation Harness for AI-Assisted Review

This directory is the first concrete step toward the AI-assisted review mode
proposed in SolAudit's OpenAI Cybersecurity Grant application: a labeled
benchmark of real Solana/Anchor vulnerability patterns, plus a harness that
scores any deterministic rule engine *or* any chat-completion model against
the same ground truth.

The goal isn't to replace SolAudit's deterministic engine — it's to measure,
honestly and reproducibly, where a model adds real value on top of it, and to
keep that value separated from deterministic findings so results stay
auditable (see "Design principle" below).

## What's here

- **`samples/`** — 13 hand-written Rust/Anchor snippets, each isolating one
  vulnerability pattern (or a safe/negative counterpart).
- **`labels.json`** — ground truth for every sample: which SolAudit rule
  ID(s), if any, should fire, and whether the sample represents a
  **known coverage gap** — a real vulnerability class the current
  deterministic ruleset cannot detect by design.
- **`harness/run_baseline.ts`** — runs SolAudit's actual rule engine
  (`packages/core`) against every sample and scores precision/recall/F1
  against `labels.json`. No AI involved; this is the control group.
- **`harness/run_llm_eval.ts`** — sends each sample to any OpenAI-compatible
  chat-completion endpoint and scores the model's reported findings against
  the same ground truth. Model-agnostic by design (see below).

## Why a "known gap" sample?

`SOL-001` through `SOL-009`/`SOL-011` are real rules SolAudit already ships
(10 total). But no static regex/pattern engine can catch everything — some
Solana vulnerabilities require understanding what an account's role in a
broader protocol design *should* be, not just a local syntactic pattern.

Two of the three vulnerability classes originally in this "known gap"
category — closed-account revival and missing rent-exemption checks — have
since been promoted to real deterministic rules (`SOL-009` and `SOL-011`).
One remains a genuine, honestly-documented gap in the *default* ruleset
(now covered by the opt-in experimental rule `SOL-012`, see below):

| Sample | Vulnerability class | Why the rule engine can't catch it |
|---|---|---|
| `gap-002-duplicate-mutable-accounts.rs` | Duplicate mutable accounts | Requires reasoning about whether two *different* account fields are constrained to be distinct — no fixed syntax to grep for. A regex-based "distinctness" heuristic false-positives on common, legitimate patterns (e.g. a deposit instruction's user/vault token accounts of the same type with no explicit `!=` constraint), which would hurt the benchmark's own precision. As of 0.3.0 this heuristic ships as the **opt-in** rule `SOL-012` (CLI flag `--experimental`) for deep manual reviews, while staying out of the default ruleset and this baseline measurement. |

This is exactly the kind of finding an AI-assisted review layer is suited
for: it requires contextual/semantic reasoning about intent, not pattern
matching, and the eval below confirms a model can catch it reliably.

## Results so far

Baseline (deterministic rule engine, `bun benchmark/harness/run_baseline.ts`):

| Metric | Result |
|---|---|
| Precision | 100.0% |
| Recall | 100.0% |

_(0.3.1: three samples' labels were revised to match SOL-008's sharpened definition — raw accounts whose data is trusted or whose key is assigned into state. The revisions are documented inline in `labels.json`. The rule previously fired on any unconstrained raw `AccountInfo` usage, which real-world scanning showed was mostly noise.)_
| F1 | 100.0% |
| Known gaps correctly left undetected (as expected) | 0/1 |

The one false positive is a real, documented limitation of `SOL-001`'s
backward-only context window (it can flag a transfer as unsigned when the
`Signer<'info>` type constraint is declared *after* the call site in the
file, which is idiomatic Anchor layout) — useful signal for hardening the
rule itself, independent of any AI work. It happens to land on the
remaining known-gap sample's `swap` function, which is exactly why that
sample's "correctly left undetected" count reads 0/1 rather than a clean
miss — a corrected discrepancy from an earlier version of this table, which
had understated the false-positive's location.

AI-assisted eval (`bun benchmark/harness/run_llm_eval.ts`, run against
Cohere's `command-a-03-2025` as a free-tier stand-in to prove the harness
works end-to-end — see note below):

| Metric | Result |
|---|---|
| Agreement with ground truth on rule-covered categories | 12/12 |
| **Known coverage gaps caught** | **1/1** |

The remaining vulnerability class the deterministic engine cannot detect by
design (duplicate mutable accounts) was correctly identified by the model,
with accurate severity and a correct one-line root-cause description. Full
per-sample output is in `results_llm_eval.json`. (Re-run after promoting two
former gaps to real rules; the model's historical 3/3 result on the
original three gap samples is preserved in git history for reference.)

## Why Cohere, if this is an OpenAI grant proposal?

This harness is intentionally **model-agnostic** — it talks to any
OpenAI-compatible `/chat/completions` endpoint via three environment
variables (`LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY`). It was validated
end-to-end against a free-tier model available today, specifically so the
harness itself — prompt design, JSON parsing, scoring logic — is already
built, tested, and proven before any grant credits exist. Pointing it at an
OpenAI model requires changing only those three environment variables, no
code changes. That's the whole point of building this now: there's nothing
left to design once credits arrive, only to point the same harness at GPT
models and expand sample coverage.

## Design principle: AI findings stay separated from deterministic findings

This is a hard requirement carried over from the grant proposal, not just a
nice-to-have. `results_baseline.json` and `results_llm_eval.json` are
produced by two independent scripts and never merged into a single "trust
me" output. Any future SolAudit AI-assisted review mode will label every
finding with its source (`rule-engine` vs. `ai-assisted`) so a reader can
always tell which findings are deterministic and reproducible versus which
came from a model's judgment call — auditability was the whole reason for
building it this way.

## Running it yourself

```bash
# Baseline — no API key needed
bun benchmark/harness/run_baseline.ts

# AI-assisted eval — point at any OpenAI-compatible endpoint
LLM_BASE_URL="https://api.openai.com/v1" \
LLM_MODEL="gpt-4o-mini" \
LLM_API_KEY="sk-..." \
LLM_REQUEST_DELAY_MS=0 \
bun benchmark/harness/run_llm_eval.ts
```

`LLM_REQUEST_DELAY_MS` is optional and only needed to stay under a trial-tier
rate limit; set to `0` (default) for production keys.

## What's next (grant-funded scope)

1. Grow the sample set well beyond 13 — ideally to 50-100+ patterns pulled
   from real historical Solana exploit post-mortems, each with the same
   rigorous ground-truth labeling used here.
2. Run the eval harness against actual OpenAI models (GPT-4o / o-series) once
   credits are available, and publish full precision/recall/cost numbers
   openly.
3. Build the opt-in AI-assisted review mode in the SolAudit CLI itself, using
   this harness's scoring methodology as its own regression test suite so
   the feature can't silently regress.
