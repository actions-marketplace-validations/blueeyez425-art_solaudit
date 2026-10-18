import { describe, expect, test } from "bun:test";
import { rules, experimentalRules } from "./index";

function ruleById(id: string) {
  const rule = [...rules, ...experimentalRules].find((r) => r.id === id);
  if (!rule) throw new Error(`rule ${id} not found`);
  return rule;
}

describe("SOL-001 Missing Signer Check", () => {
  test("flags transfer with no signer evidence nearby", () => {
    const src = `
      pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let cpi_accounts = Transfer {
          from: ctx.accounts.vault_token_account.to_account_info(),
          to: ctx.accounts.user_token_account.to_account_info(),
          authority: ctx.accounts.vault_authority.to_account_info(),
        };
        token::transfer(cpi_ctx, amount)?;
        Ok(())
      }
    `;
    const findings = ruleById("SOL-001").check(src, "test.rs");
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe("SOL-001");
  });

  test("does not flag when is_signer check is nearby", () => {
    const src = `
      pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        require!(ctx.accounts.authority.is_signer, ErrorCode::Unauthorized);
        token::transfer(cpi_ctx, amount)?;
        Ok(())
      }
    `;
    const findings = ruleById("SOL-001").check(src, "test.rs");
    expect(findings.length).toBe(0);
  });
});

describe("SOL-004 Missing Bump Seed Canonicalization", () => {
  test("flags create_program_address without find_program_address", () => {
    const src = `let pda = Pubkey::create_program_address(seeds, program_id)?;`;
    const findings = ruleById("SOL-004").check(src, "test.rs");
    expect(findings.length).toBe(1);
  });

  test("does not flag find_program_address with bump destructured", () => {
    const src = `let (pda, bump) = Pubkey::find_program_address(seeds, program_id);`;
    const findings = ruleById("SOL-004").check(src, "test.rs");
    expect(findings.length).toBe(0);
  });
});

describe("SOL-005 Integer Overflow Risk", () => {
  test("flags raw arithmetic on balance-like fields", () => {
    const src = `vault.total_staked = vault.total_staked + amount;`;
    const findings = ruleById("SOL-005").check(src, "test.rs");
    expect(findings.length).toBe(1);
  });

  test("does not flag checked arithmetic", () => {
    const src = `vault.total_staked = vault.total_staked.checked_add(amount).ok_or(ErrorCode::MathOverflow)?;`;
    const findings = ruleById("SOL-005").check(src, "test.rs");
    expect(findings.length).toBe(0);
  });
});

describe("SOL-007 Insecure Account Initialization", () => {
  test("flags init without space", () => {
    const src = `#[account(init, payer = authority)]\npub vault: Account<'info, Vault>,`;
    const findings = ruleById("SOL-007").check(src, "test.rs");
    expect(findings.length).toBe(1);
  });

  test("does not flag init with payer and space", () => {
    const src = `#[account(init, payer = authority, space = 8 + 32 + 8)]\npub vault: Account<'info, Vault>,`;
    const findings = ruleById("SOL-007").check(src, "test.rs");
    expect(findings.length).toBe(0);
  });
});

describe("SOL-009 Insecure Manual Account Closure", () => {
  test("flags manual lamport-zeroing with no discriminator zeroing or close constraint nearby", () => {
    const src = `
      pub fn close_position(ctx: Context<ClosePosition>) -> Result<()> {
        let position = ctx.accounts.position.to_account_info();
        let destination = ctx.accounts.destination.to_account_info();
        **destination.lamports.borrow_mut() = destination.lamports().checked_add(position.lamports()).unwrap();
        **position.lamports.borrow_mut() = 0;
        Ok(())
      }
    `;
    const findings = ruleById("SOL-009").check(src, "test.rs");
    expect(findings.length).toBe(1);
  });

  test("does not flag when discriminator zeroing is nearby", () => {
    const src = `
      pub fn close_position(ctx: Context<ClosePosition>) -> Result<()> {
        **position.lamports.borrow_mut() = 0;
        let mut data = position.try_borrow_mut_data()?;
        data[..8].copy_from_slice(&CLOSED_ACCOUNT_DISCRIMINATOR);
        Ok(())
      }
    `;
    const findings = ruleById("SOL-009").check(src, "test.rs");
    expect(findings.length).toBe(0);
  });

  test("does not flag Anchor's close = constraint usage", () => {
    const src = `#[account(mut, close = destination)]\npub position: Account<'info, Position>,`;
    const findings = ruleById("SOL-009").check(src, "test.rs");
    expect(findings.length).toBe(0);
  });
});

describe("SOL-010 Reinitialization Risk via init_if_needed", () => {
  test("flags init_if_needed account constraints", () => {
    const src = `#[account(init_if_needed, payer = authority, space = 8 + 32)]\npub record: Account<'info, Record>,`;
    const findings = ruleById("SOL-010").check(src, "test.rs");
    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe("SOL-010");
  });

  test("does not flag plain init", () => {
    const src = `#[account(init, payer = authority, space = 8 + 32)]\npub vault: Account<'info, Vault>,`;
    const findings = ruleById("SOL-010").check(src, "test.rs");
    expect(findings.length).toBe(0);
  });
});

describe("SOL-012 Duplicate Mutable Accounts (experimental)", () => {
  test("flags two mutable accounts of the same type with no distinctness constraint", () => {
    const src = `
      #[derive(Accounts)]
      pub struct Swap<'info> {
        #[account(mut)]
        pub account_a: Account<'info, TokenAccount>,
        #[account(mut)]
        pub account_b: Account<'info, TokenAccount>,
        pub authority: Signer<'info>,
      }
    `;
    const findings = ruleById("SOL-012").check(src, "test.rs");
    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe("SOL-012");
  });

  test("does not flag when an inequality constraint forces distinctness", () => {
    const src = `
      #[derive(Accounts)]
      pub struct Swap<'info> {
        #[account(mut)]
        pub account_a: Account<'info, TokenAccount>,
        #[account(mut, constraint = account_b.key() != account_a.key())]
        pub account_b: Account<'info, TokenAccount>,
        pub authority: Signer<'info>,
      }
    `;
    const findings = ruleById("SOL-012").check(src, "test.rs");
    expect(findings.length).toBe(0);
  });

  test("does not flag mutable accounts of different types", () => {
    const src = `
      #[derive(Accounts)]
      pub struct Deposit<'info> {
        #[account(mut)]
        pub vault: Account<'info, Vault>,
        #[account(mut)]
        pub user_token: Account<'info, TokenAccount>,
        pub owner: Signer<'info>,
      }
    `;
    const findings = ruleById("SOL-012").check(src, "test.rs");
    expect(findings.length).toBe(0);
  });
});

describe("SOL-011 Missing Rent-Exemption Check", () => {
  test("flags partial lamport withdrawal with no rent check nearby", () => {
    const src = `
      pub fn partial_withdraw(ctx: Context<PartialWithdraw>, lamports: u64) -> Result<()> {
        **vault.lamports.borrow_mut() = vault.lamports().checked_sub(lamports).unwrap();
        Ok(())
      }
    `;
    const findings = ruleById("SOL-011").check(src, "test.rs");
    expect(findings.length).toBe(1);
  });

  test("does not flag when a Rent::minimum_balance check is nearby", () => {
    const src = `
      pub fn partial_withdraw(ctx: Context<PartialWithdraw>, lamports: u64) -> Result<()> {
        let min_balance = Rent::get()?.minimum_balance(vault.data_len());
        require!(vault.lamports() - lamports >= min_balance, ErrorCode::BelowRentExempt);
        **vault.lamports.borrow_mut() = vault.lamports().checked_sub(lamports).unwrap();
        Ok(())
      }
    `;
    const findings = ruleById("SOL-011").check(src, "test.rs");
    expect(findings.length).toBe(0);
  });

  test("does not flag a full drain to zero (handled by SOL-009 instead)", () => {
    const src = `**vault.lamports.borrow_mut() = 0;`;
    const findings = ruleById("SOL-011").check(src, "test.rs");
    expect(findings.length).toBe(0);
  });
});

describe("rules registry", () => {
  test("exposes exactly 11 default rules with unique ids", () => {
    expect(rules.length).toBe(11);
    const ids = new Set(rules.map((r) => r.id));
    expect(ids.size).toBe(11);
  });

  test("experimental rules are excluded from the default set", () => {
    const defaultIds = new Set(rules.map((r) => r.id));
    for (const rule of experimentalRules) {
      expect(defaultIds.has(rule.id)).toBe(false);
    }
  });
});
