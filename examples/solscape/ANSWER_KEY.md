# SolScape — Answer Key (seeded vulnerabilities)

Written BEFORE the scanner run. This is the ground truth the SolAudit scorecard is
measured against. Each entry: location, class, expected rule, why it's exploitable.

## Seeded bugs (expected to be caught)

| # | Handler | Vuln class | Expected rule(s) | Exploit sketch |
|---|---|---|---|---|
| B1 | `register_player` | Reinitialization via `init_if_needed` | SOL-010 | Re-register to wipe XP / stats back to zero after penalties |
| B2 | `upgrade_tile` | Unchecked arithmetic in price curve | SOL-005 | `fee = base * 2^level * tiles_owned` overflows u64 at high level → fee wraps to ~0 |
| B3 | `buy_tile` | Trusts raw account data without validation | SOL-008 | Pass a fake "tile" account with crafted owner/price bytes; program pays out based on attacker-controlled data |
| B4 | `buy_tile_spl` | Arbitrary CPI target (token program unchecked) | SOL-007 | Attacker passes a malicious "token program"; CPI executes attacker code |
| B5 | `buy_tile_spl` | Token account mint never bound to expected mint | SOL-013 (experimental) | Pay with worthless tokens instead of the official fee token (Cashio class) |
| B6 | `close_tile` | Manual lamport drain / close-then-revive | SOL-009 | Drained tile account can be revived in the same tx → resurrected with stale owner |
| B7 | `withdraw_treasury` | Missing signer check on authority | SOL-001 | Anyone calls withdraw with the authority's pubkey as a non-signer → drains all fees |
| B8 | `withdraw_treasury` | Treasury PDA not verified against derived address | SOL-004 | Substitute an attacker-owned account as "treasury" |
| B9 | `grant_achievement` | Missing owner check on profile account | SOL-002 | Pass a fake profile account owned by an attacker program → arbitrary XP grant |

## Controls (expected NOT to be flagged)

| # | Handler | Why clean |
|---|---|---|
| C1 | `initialize` | Proper `init`, seeds, signer authority |
| C2 | `claim_tile` | `Signer`, PDA via `seeds`+`bump`, fee via system program CPI with explicit program id |
| C3 | `list_tile` | `has_one = owner`, `Signer`, no CPI |
| C4 | `harvest` | `checked_mul` / `checked_sub` math, `has_one` constraints |

## Scoring

- True positive: rule fires at the seeded location (handler-level match is enough; line
  numbers drift).
- False positive: any finding on a control handler for the class it was designed to be
  clean against.
- Score = TP / 9, FP / 4-controls.
