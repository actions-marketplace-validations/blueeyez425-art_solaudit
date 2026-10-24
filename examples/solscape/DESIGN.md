# SolScape — Design Doc (v0.1)

**Concept:** a persistent on-chain territory map on Solana. Players claim tiles on a shared
100×100 grid, upgrade them, and trade them in a built-in marketplace. All fees flow to an
on-chain treasury controlled by the game authority. No wagering, no randomness — a paid
persistent-world game, not a casino.

## Why this game (for SolAudit)

Every core mechanic maps to a real vulnerability class SolAudit detects:

| Mechanic | Value at risk | Vuln surface |
|---|---|---|
| Claiming tiles (SOL fee → treasury) | escrowed SOL | PDA derivation, CPI |
| Upgrading (price curve) | fee math | integer overflow |
| Marketplace (player-to-player sales) | player funds | signer checks, account substitution, arbitrary CPI |
| Player profiles (XP) | account state | reinitialization via init_if_needed |
| Closing abandoned tiles | lamport recovery | close-then-revive |
| Treasury withdrawals | all fees | missing signer, unvalidated PDA |

## Accounts

- `Config` — PDA `[b"config"]`: authority, claim fee, royalty bps.
- `Treasury` — PDA `[b"treasury"]`: system-owned vault holding all fees.
- `Tile` — PDA `[b"tile", x_le, y_le]`: owner, level, list price (0 = not for sale).
- `PlayerProfile` — PDA `[b"player", owner]`: XP, tiles claimed.

## Instructions (v1)

1. `initialize` — create config + treasury (clean, control).
2. `register_player` — create profile (SEEDED: reinit via init_if_needed).
3. `claim_tile(x, y)` — pay fee, create tile (clean, control).
4. `upgrade_tile` — pay level-scaled fee (SEEDED: unchecked overflow in price curve).
5. `list_tile(price)` — list owned tile for sale (clean, control).
6. `buy_tile` — SOL purchase; pays seller minus royalty (SEEDED: trusts seller account data).
7. `buy_tile_spl` — SPL-token purchase variant (SEEDED: arbitrary token program CPI, unvalidated mint).
8. `close_tile` — reclaim rent from a tile (SEEDED: manual close, close-then-revive).
9. `withdraw_treasury(amount)` — authority withdraws fees (SEEDED: missing signer, unvalidated treasury PDA).
10. `grant_achievement(xp)` — oracle-style XP grant reading a profile (SEEDED: missing owner check).
11. `harvest` — periodic fee rebate with checked math (clean, control).

## Revenue model (fixed version)

- Claim fee per tile (e.g., 0.01 SOL) → treasury.
- Upgrade fees → treasury.
- Marketplace royalty (e.g., 5% of each sale) → treasury; seller gets the rest.
- No player-vs-program wagering anywhere. Players can profit only by selling tiles to
  other players at market prices — a normal game economy.

## Hard rules

- The public deployable version is the FIXED build. The vulnerable build is a clearly
  labeled test fixture only.
- Nothing ships to mainnet with seeded bugs. Ever.
