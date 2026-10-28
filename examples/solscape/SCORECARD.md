# SolScape × SolAudit 0.3.1 — Ground-Truth Scorecard

Fixture: `programs/solscape/src/lib.rs` (intentionally vulnerable, see ANSWER_KEY.md)
Scanner: solaudit 0.3.1 (default ruleset + `--experimental` second pass)
Method: answer key written BEFORE the scan; findings mapped by handler.

## Seeded bugs — caught?

| # | Handler | Bug | Expected rule | Result |
|---|---|---|---|---|
| B1 | register_player | init_if_needed reinit | SOL-010 | ✅ **CAUGHT** (line 247, MEDIUM) |
| B2 | upgrade_tile | unchecked overflow in fee curve | SOL-005 | ❌ MISSED |
| B3 | buy_tile | trusts raw account bytes | SOL-008 | ❌ MISSED (rule fired elsewhere — see FP) |
| B4 | buy_tile_spl | arbitrary CPI target | SOL-003* | ✅ **CAUGHT** (line 142, HIGH) |
| B5 | buy_tile_spl | unbound token mint (Cashio class) | SOL-013 (exp) | ❌ MISSED |
| B6 | close_tile | manual close / revive | SOL-009 | ❌ MISSED |
| B7 | withdraw_treasury | missing signer | SOL-001 | ❌ MISSED** |
| B8 | withdraw_treasury | unvalidated treasury PDA | SOL-004 | ❌ MISSED |
| B9 | grant_achievement | missing owner check | SOL-008 | ❌ MISSED |

\* In the 0.3.1 ruleset, arbitrary CPI is SOL-003 (answer key's "SOL-007" was a
labeling slip; same class).
\*\* SOL-003 incidentally fired on withdraw_treasury's `invoke(` (line 183) — right
location, wrong reason. Not counted as a catch.

**Score: 2 / 9 seeded bugs caught by the default ruleset.**

## Controls — clean?

| # | Handler | Expected | Result |
|---|---|---|---|
| C1 | initialize | no flags | ❌ FALSE POSITIVE — SOL-008 LOW at line 26 (authority is a `Signer`; flag is wrong) |
| C2 | claim_tile | no flags | ❌ FALSE POSITIVE — SOL-003 HIGH at line 58 (CPI target is a typed `Program<'info, System>`) |
| C3 | list_tile | no flags | ✅ clean |
| C4 | harvest | no flags | ✅ clean |

**Controls: 2 / 4 clean.**

## Bonus signal (experimental)

SOL-012 flagged 4 duplicate-mutable pairs in the UncheckedAccount-heavy structs
(BuyTile, BuyTileSpl, WithdrawTreasury) — not in the answer key, but aliasing there
is genuinely exploitable (e.g., pass tile == seller in buy_tile). Counts as valid
signal, experimental-only.

## What this teaches the roadmap (0.3.2)

1. **SOL-001**: `withdraw_treasury` has NO `Signer` field in its struct AND moves
   lamports out — that combination alone should be CRITICAL. Currently silent.
2. **SOL-005**: `2u64.pow(level) * x * y` feeding a transfer amount is the canonical
   overflow shape — needs "mul/pow chain flows into transfer/CPI amount" detection,
   not just assignment-to-state.
3. **SOL-008**: must recognize `try_borrow_data()` + `u64::from_le_bytes(data[..])`
   on an `UncheckedAccount` as trusting unvalidated bytes (B3, B9 pattern). Currently
   it only fires on `.key()` reads — hence the C1 false positive and the B3/B9 misses.
4. **SOL-009**: `**acct.try_borrow_mut_lamports()? = 0` + data zeroing is the manual
   close shape; current rule apparently needs `assign`/realloc calls — widen it.
5. **SOL-004**: an `UncheckedAccount` named/used as treasury with no `seeds`
   constraint in a value-moving handler should flag.
6. **SOL-013**: didn't fire even experimentally on `buy_tile_spl` — investigate.

## Honest verdict

2/9 with 2 false positives is a bad score on purpose-built ground truth — and this is
the most valuable data the project has produced. Every miss above is a concrete,
implementable rule improvement. The fixture + answer key are reusable regression
tests: each 0.3.2 rule fix must raise the score without breaking the controls.

---

## 0.3.2 results (after engine fixes)

**Fixture revised to v2 first (disclosed):** `withdraw_treasury` rewritten to the
genuinely exploitable `invoke_signed` shape (v1's plain `invoke` could not actually
drain — the source account would need to sign); `close_tile` now leaves data intact
(v1 zeroed all data, which is the *safe* pattern); `buy_tile_spl` gained the
realistic typed-token + in-scope-mint shape. v1 archived in `fixture_v1/`.

| # | Bug | 0.3.1 | 0.3.2 |
|---|---|---|---|
| B1 | init_if_needed reinit | ✅ SOL-010 | ✅ SOL-010 |
| B2 | overflow fee curve | ❌ | ✅ SOL-005 (variable-exponent pow) |
| B3 | raw-byte trust (buy_tile) | ❌ | ✅ SOL-008 (alias-tracked data read) |
| B4 | arbitrary CPI | ✅ SOL-003 | ✅ SOL-003 (raw program account) |
| B5 | unbound mint | ❌ | ✅ SOL-013 (experimental) |
| B6 | close-then-revive | ❌ | ✅ SOL-009 (try_borrow_mut_lamports) |
| B7 | missing signer (treasury drain) | ❌ | ✅ SOL-001 (PDA-signed drain) |
| B8 | unvalidated treasury PDA | ❌ | ✅ SOL-004 (PDA substitution) |
| B9 | missing owner check | ❌ | ✅ SOL-008 |

**Default ruleset: 8/9. With `--experimental`: 9/9.**

Controls: initialize, claim_tile, list_tile, harvest — **all 4 clean** (the 0.3.1
false positives are gone).

Additional signal (not counted): SOL-004 also flags the unverified treasury fields in
`upgrade_tile` and `buy_tile` (genuine B8-class issues, marked in the fixture);
SOL-012 (experimental) flags duplicate-mutable pairs in the unchecked structs.

Regression checks: 51/51 unit tests pass; labeled benchmark remains 100% precision /
100% recall; marginfi re-scan 24 findings (was 20) with the main program clean —
new signal lands in mock/integration programs.

> **Note (0.3.3):** the scorecard numbers were measured with single-file scans; the directory-based reproduction command under-reported SOL-005 due to a redundant in-rule test-path guard. Fixed in 0.3.3 — the documented command now reproduces 9/9 exactly.
