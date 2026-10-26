# SolScape — intentionally vulnerable test fixture

SolScape is a complete Anchor game program (a persistent on-chain territory map with
a marketplace, treasury, and player profiles) that is **deliberately seeded with 9
real exploit classes**, plus 4 correctly-secured control handlers.

**⚠️ DO NOT DEPLOY. This code is vulnerable by design. ⚠️**

- `DESIGN.md` — the game design and why each mechanic maps to a vuln class
- `ANSWER_KEY.md` — the ground truth (written before the scanner run)
- `SCORECARD.md` — 0.3.1 vs 0.3.2 results against the answer key
- `programs/solscape/src/lib.rs` — the vulnerable program (v2)
- `programs/solscape-fixed/src/lib.rs` — the HARDENED build (all 9 classes fixed; see below)
- `fixture_v1/` — the archived v1 fixture (revisions disclosed in SCORECARD.md)

Scan it yourself (the CLI excludes example dirs by default, so opt in):

```bash
solaudit examples/solscape/programs --include-tests
solaudit examples/solscape/programs --include-tests --experimental  # catches 9/9
```

## The hardened build (`programs/solscape-fixed/`)

`solscape-fixed` is the same game with every seeded bug class fixed — this is the only
version that may ever be deployed. The fix for each class (also noted inline in the code):

| Bug | Fix |
|---|---|
| B1 reinit | `init_if_needed` → `init` |
| B2 overflow | checked math + explicit `MAX_LEVEL` cap on the price curve |
| B3 fake tile account | typed `Account<Tile>` + PDA seeds + `has_one = seller` |
| B4 arbitrary CPI | `token_program: Program<Token>` (program id enforced by Anchor) |
| B5 unbound mint (Cashio class) | `token::mint = mint` on both token accounts |
| B6 close-then-revive | Anchor `close =` constraint (data zeroed, ownership reset) |
| B7 missing signer | `authority: Signer` + `has_one` against config |
| B8 unverified treasury PDA | `seeds = [b"treasury"], bump` on the treasury account |
| B9 fake profile | typed `Account<PlayerProfile>` (discriminator + owner enforced) |

**SolAudit 0.3.2 result on the hardened build: 0 findings, default and `--experimental`.**

One honest footnote: during hardening, the experimental SOL-012 rule caught a real
residual bug the answer key didn't plan for — a self-payment attack (passing the same
account as `buyer_token` and `seller_token`, making the SPL transfer a no-op and taking
the tile for free). Fixed with a distinctness constraint. The scanner earning its keep
on code we *thought* was clean is the best endorsement it could get.
