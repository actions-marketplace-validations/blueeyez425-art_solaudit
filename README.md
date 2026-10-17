# SolAudit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![npm version](https://img.shields.io/badge/npm-v0.3.0-blue.svg)](https://www.npmjs.com/package/solaudit)
[![build](https://img.shields.io/badge/build-passing-brightgreen.svg)](./.github/workflows/ci.yml)

**A zero-dependency static-analysis engine that scans Anchor/Solana Rust programs for the vulnerability patterns behind the most common on-chain exploits — available as a CLI and as a free web app.**

SolAudit reads `.rs` source files, applies a set of pattern-matching security rules (missing signer checks, arbitrary CPIs, unchecked deserialization, integer overflow, and more), and gives you an actionable report in seconds — no RPC calls, no wallet, no build step required to run it.

- **CLI** — `npx solaudit ./program`, for local development and CI.
- **Web app** — [solaudit-web.vercel.app](https://solaudit-web.vercel.app/) — paste a public GitHub repo URL or upload a single `.rs` file, no install required.

---

## Repository layout

This is a Bun workspaces monorepo. The CLI and the web app share one scanning engine, so there is a single source of truth for every rule — no drift between the two.

```
packages/core/    Shared engine: rules, scanner, output formatters (published nowhere; workspace-only)
cli/              npm package "solaudit" — the command-line tool
web/              Next.js app deployed to Vercel — the web version
examples/         Intentionally vulnerable sample Anchor program, used by both the CLI and web tests
```

## CLI

```bash
# Run instantly with npx (no install)
npx solaudit ./program

# Or install globally with Bun
bun add -g solaudit
solaudit ./program
```

```bash
solaudit [path] [options]
```

| Flag | Description |
|---|---|
| `--json` | Print raw scan results as JSON |
| `--sarif` | Print results as SARIF 2.1.0 (for GitHub Code Scanning) |
| `--min-severity <level>` | Only report findings at or above `CRITICAL`\|`HIGH`\|`MEDIUM`\|`LOW`\|`INFO` |
| `--experimental` | Also run opt-in experimental rules (currently `SOL-012` Duplicate Mutable Accounts); higher signal, more false positives |
| `--help` | Show usage |

### Example

```bash
$ solaudit ./examples
```

```
SolAudit v0.3.0 — static analysis for Anchor/Solana programs
Scanned 1 file(s) at 2026-08-27T06:00:00.000Z
──────────────────────────────────────────────────────────────────────

CRITICAL (2)
   CRITICAL  SOL-001 Missing Signer Check
    examples/vulnerable.rs:35
    │ token::transfer(cpi_ctx, amount)?;
    └─ Verify the authority/owner account is a Signer or explicitly
       check `.is_signer` before transferring or minting tokens.

──────────────────────────────────────────────────────────────────────
Summary
  CRITICAL 2   HIGH 3   MEDIUM 3   LOW 6   INFO 0
  Total findings: 14 across 1 file(s)
```

Exit code is `1` when any `CRITICAL` or `HIGH` finding is present — making SolAudit a natural CI gate.

## Web app

**Live at [solaudit-web.vercel.app](https://solaudit-web.vercel.app/)** — no CLI, no local Anchor toolchain, no wallet required:

1. Paste a public GitHub repo URL **or** upload a single `.rs` file.
2. The server fetches `.rs` files via GitHub's API (no `git clone`) and scans them with the exact same engine as the CLI.
3. Get a report grouped by severity, right in the browser.

Optional: set `GITHUB_TOKEN` (see `web/.env.example`) to raise the GitHub API rate limit from 60 to 5,000 requests/hour. No special token scopes are needed for public repos.

### Running the web app locally

```bash
bun install          # from the repo root — links the workspace packages
cd web
bun run dev
```

## Rules

| ID | Severity | Name | What it catches |
|---|---|---|---|
| `SOL-001` | CRITICAL | Missing Signer Check | `transfer`/`mint_to` calls made without a nearby `Signer<'info>` type or `.is_signer` check |
| `SOL-002` | HIGH | Unchecked Account Deserialization | `Account::try_from` / `AccountLoader::try_from` used without a validating `#[account(...)]` constraint |
| `SOL-003` | HIGH | Arbitrary CPI | `invoke`/`invoke_signed` targeting a program ID sourced from a caller-supplied account instead of a verified constant |
| `SOL-004` | HIGH | Missing Bump Seed Canonicalization | `create_program_address` used directly, or `find_program_address`'s bump discarded instead of stored/validated |
| `SOL-005` | MEDIUM | Integer Overflow Risk | Raw `+`/`-`/`*` arithmetic on balance-like fields instead of `checked_*`/`saturating_*` |
| `SOL-006` | HIGH | Type Cosplay / Missing Discriminator Check | Manual `try_from_slice` deserialization with no discriminator validation or `Account<'info, T>` wrapper |
| `SOL-007` | MEDIUM | Insecure Account Initialization | `#[account(init, ...)]` constraints missing `payer` and/or `space` |
| `SOL-008` | LOW | Missing Owner Check | Raw `AccountInfo` fields used without a nearby `.owner` comparison |
| `SOL-009` | HIGH | Insecure Manual Account Closure | An account's lamports manually drained to zero without discriminator zeroing or owner reassignment (unlike Anchor's `close = destination`), enabling closed-account revival |
| `SOL-010` | MEDIUM | Reinitialization Risk via init_if_needed | `#[account(init_if_needed, ...)]` without canonical PDA seeds / `has_one` constraints, letting a pre-existing attacker-crafted account pass as freshly initialized |
| `SOL-011` | MEDIUM | Missing Rent-Exemption Check | A partial lamport withdrawal with no nearby `Rent::get()?.minimum_balance(...)` check, risking runtime garbage-collection of the account |

Each rule is implemented as real regex/line-scanning logic in [`packages/core/src/rules/index.ts`](./packages/core/src/rules/index.ts) — see that file (and its accompanying [tests](./packages/core/src/rules/index.test.ts)) for the exact matching heuristics and false-positive guards.

## Accuracy

On the committed labeled suite in [`benchmark/`](./benchmark), the deterministic engine scores **94.1% precision, 100% recall, 97.0% F1** on rule-covered categories.

**Duplicate mutable accounts** is covered by the experimental `SOL-012` rule, available via `solaudit --experimental`. A “distinctness” heuristic false-positives on common legitimate patterns (for example a deposit instruction’s user/vault token accounts of the same type with no explicit `!=` constraint), so it stays opt-in to protect the default ruleset's precision. These numbers describe this suite, not general security effectiveness.

## Output formats (CLI)

- **Human** (default) — colorized terminal report grouped by severity.
- **JSON** (`--json`) — the full `ScanResult` object (`scannedFiles`, `findings[]`, `summary`).
- **SARIF** (`--sarif`) — [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) output compatible with GitHub Code Scanning.
- **Experimental rules** (`--experimental`) — opt into noisier, higher-signal heuristics (currently `SOL-012` Duplicate Mutable Accounts). Recommended for deep manual reviews rather than CI gates.

## GitHub Actions

SolAudit ships as a ready-to-use [GitHub Action](./action.yml). Drop this into `.github/workflows/solaudit.yml` in your own repo and every push/PR gets scanned automatically, with results uploaded straight to your repo's Security tab:

```yaml
name: SolAudit

on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # required to upload SARIF results

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: blueeyez425-art/solaudit@main
        with:
          path: ./programs        # file or directory to scan (default: .)
          min-severity: INFO      # lowest severity to report (default: INFO)
          fail-on-findings: true  # fail the build on any CRITICAL/HIGH finding (default: true)
          upload-sarif: true      # upload results to code scanning (default: true)
```

No `security-events: write` permission in your workflow? Set `upload-sarif: false` and the action will still run the scan and fail the build on CRITICAL/HIGH findings — it just won't publish to the Security tab.

Prefer to wire it up manually instead of using the packaged action:

```yaml
- uses: actions/checkout@v4
- run: npx solaudit ./programs --sarif > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

This repository's own [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) runs the full test suite, builds the CLI and web app, and uses this repo's own action against `examples/` on every push.

## Development

```bash
bun install                    # installs and links all workspaces
cd packages/core && bun test   # run the engine's unit test suite
cd cli && bun run build        # bundle cli/src/cli.ts -> cli/dist/cli.js
cd web && bun run build        # production-build the web app
```

## Contributing

Contributions are very welcome — new rules, false-positive fixes, additional output formats, or web UI improvements are all in scope.

1. Fork the repo and create a branch from `main`.
2. Add or update a rule in `packages/core/src/rules/index.ts` (each rule is a self-contained `Rule` object).
3. Add unit tests covering both a triggering and a non-triggering case (`packages/core/src/rules/index.test.ts`).
4. Run `bun test` (from `packages/core`) before opening a PR.

Please open an issue first for larger changes so we can discuss the approach.

## Support

SolAudit is free and open source, and development continues with or without tips. If it catches a bug or saves you real time and you'd like to say thanks, tips are appreciated — never expected: [flipcash.com/d142ad60-e966-4967-bfa3-6d2332e59342](https://flipcash.com/d142ad60-e966-4967-bfa3-6d2332e59342)

## License

[MIT](./LICENSE) © 2026 Cody Pack
