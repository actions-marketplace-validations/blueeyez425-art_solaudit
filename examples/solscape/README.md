# SolScape — intentionally vulnerable test fixture

SolScape is a complete Anchor game program (a persistent on-chain territory map with
a marketplace, treasury, and player profiles) that is **deliberately seeded with 9
real exploit classes**, plus 4 correctly-secured control handlers.

**⚠️ DO NOT DEPLOY. This code is vulnerable by design. ⚠️**

- `DESIGN.md` — the game design and why each mechanic maps to a vuln class
- `ANSWER_KEY.md` — the ground truth (written before the scanner run)
- `SCORECARD.md` — 0.3.1 vs 0.3.2 results against the answer key
- `programs/solscape/src/lib.rs` — the vulnerable program (v2)
- `fixture_v1/` — the archived v1 fixture (revisions disclosed in SCORECARD.md)

Scan it yourself (the CLI excludes example dirs by default, so opt in):

```bash
solaudit examples/solscape/programs --include-tests
solaudit examples/solscape/programs --include-tests --experimental  # catches 9/9
```
