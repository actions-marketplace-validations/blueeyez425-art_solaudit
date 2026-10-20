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

describe("constraint-layer awareness (0.3.1)", () => {
  const IDIOMATIC = `
    #[derive(Accounts)]
    pub struct Withdraw<'info> {
      #[account(mut, has_one = authority)]
      pub vault: Account<'info, Vault>,
      #[account(mut)]
      pub vault_token_account: Account<'info, TokenAccount>,
      #[account(mut)]
      pub destination_token_account: Account<'info, TokenAccount>,
      pub authority: Signer<'info>,
      pub token_program: Program<'info, Token>,
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
      let cpi_accounts = Transfer {
        from: ctx.accounts.vault_token_account.to_account_info(),
        to: ctx.accounts.destination_token_account.to_account_info(),
        authority: ctx.accounts.authority.to_account_info(),
      };
      let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
      token::transfer(cpi_ctx, amount)?;
      Ok(())
    }
  `;

  test("SOL-001: does not flag a transfer when the governing struct declares a Signer", () => {
    const findings = ruleById("SOL-001").check(IDIOMATIC, "test.rs");
    expect(findings.length).toBe(0);
  });

  test("SOL-001: still flags when the struct has no Signer field", () => {
    const src = IDIOMATIC.replace("pub authority: Signer<'info>,", "pub authority: AccountInfo<'info>,");
    const findings = ruleById("SOL-001").check(src, "test.rs");
    expect(findings.length).toBeGreaterThan(0);
  });

  test("SOL-001: does not flag PDA-signed CPI (invoke_signed nearby)", () => {
    const src = `
      pub fn withdraw(ctx: Context<Withdraw>, amount: u64, bump: u8) -> Result<()> {
        let cpi_accounts = Transfer {
          from: ctx.accounts.vault_token_account.to_account_info(),
          to: ctx.accounts.destination_token_account.to_account_info(),
          authority: ctx.accounts.vault_authority.to_account_info(),
        };
        let seeds = &[&[b"vault", &[bump]]];
        let cpi_ctx = CpiContext::new_with_signer(ctx.accounts.token_program.to_account_info(), cpi_accounts, seeds);
        token::transfer(cpi_ctx, amount)?;
        Ok(())
      }
    `;
    const findings = ruleById("SOL-001").check(src, "test.rs");
    expect(findings.length).toBe(0);
  });

  test("SOL-001: does not flag a format string that merely mentions transfer", () => {
    const src = `
      pub fn check(ctx: Context<Check>, amount: u64) -> Result<()> {
        require!(amount <= MAX, ErrorCode::TooBig);
        msg!("Max transfer ({}) exceeded", amount);
        Ok(())
      }
    `;
    const findings = ruleById("SOL-001").check(src, "test.rs");
    expect(findings.length).toBe(0);
  });

  test("SOL-004: does not flag find_program_address with the .0 accessor", () => {
    const src = `
      pub fn derive_it(program_id: &Pubkey) -> Pubkey {
        let pda = Pubkey::find_program_address(&[b"vault"], program_id).0;
        pda
      }
    `;
    const findings = ruleById("SOL-004").check(src, "test.rs");
    expect(findings.length).toBe(0);
  });

  test("SOL-005: does not flag intermediate tuple arithmetic", () => {
    const src = `
      pub fn split(ctx: Context<Split>, amount_owed: u64, vault_amount: u64) -> Result<()> {
        let (from_vault, remainder) = (vault_amount, amount_owed - vault_amount);
        Ok(())
      }
    `;
    const findings = ruleById("SOL-005").check(src, "test.rs");
    expect(findings.length).toBe(0);
  });

  test("SOL-005: still flags raw arithmetic written into account state", () => {
    const src = `
      pub fn stake(ctx: Context<Stake>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.total_staked = pool.total_staked + amount;
        Ok(())
      }
    `;
    const findings = ruleById("SOL-005").check(src, "test.rs");
    expect(findings.length).toBe(1);
  });

  test("SOL-005: does not flag code inside #[cfg(test)] modules", () => {
    const src = `
      pub fn stake(ctx: Context<Stake>, amount: u64) -> Result<()> {
        Ok(())
      }
      #[cfg(test)]
      mod tests {
        fn exercises() {
          pool.total_staked = pool.total_staked + amount;
        }
      }
    `;
    const findings = ruleById("SOL-005").check(src, "test.rs");
    expect(findings.length).toBe(0);
  });

  test("SOL-008: does not flag raw fields validated by a constraint in the file", () => {
    const src = `
      #[derive(Accounts)]
      pub struct Init<'info> {
        #[account(constraint = state.signer.eq(&drift_signer.key()))]
        /// CHECK: program signer
        pub drift_signer: AccountInfo<'info>,
        pub state: Account<'info, State>,
      }
      pub fn handle(ctx: Context<Init>) -> Result<()> {
        initialize_token_account(&ctx.accounts.token_program, &ctx.accounts.drift_signer)?;
        Ok(())
      }
    `;
    const findings = ruleById("SOL-008").check(src, "test.rs");
    expect(findings.length).toBe(0);
  });

  test("SOL-008: flags an unconstrained raw field once, not per usage", () => {
    const src = `
      #[derive(Accounts)]
      pub struct Consume<'info> {
        /// CHECK: no validation
        pub price_feed: AccountInfo<'info>,
      }
      pub fn consume(ctx: Context<Consume>) -> Result<()> {
        let a = ctx.accounts.price_feed.try_borrow_data()?;
        let b = ctx.accounts.price_feed.key();
        Ok(())
      }
    `;
    const findings = ruleById("SOL-008").check(src, "test.rs");
    expect(findings.length).toBe(1);
  });

  test("SOL-013: flags a token account not bound to an in-scope mint (Cashio class)", () => {
    const src = `
      #[derive(Accounts)]
      pub struct Brrr<'info> {
        pub bank: Box<Account<'info, Bank>>,
        #[account(mut)]
        pub crate_mint: Box<Account<'info, Mint>>,
        #[account(mut)]
        pub crate_collateral_tokens: Box<Account<'info, TokenAccount>>,
      }
    `;
    const findings = ruleById("SOL-013").check(src, "test.rs");
    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe("SOL-013");
  });

  test("SOL-013: does not flag when the token account is bound via token::mint", () => {
    const src = `
      #[derive(Accounts)]
      pub struct Redeem<'info> {
        #[account(mut)]
        pub mint: Account<'info, Mint>,
        #[account(mut, token::mint = mint, token::authority = authority)]
        pub user_token: Account<'info, TokenAccount>,
        pub authority: Signer<'info>,
      }
    `;
    const findings = ruleById("SOL-013").check(src, "test.rs");
    expect(findings.length).toBe(0);
  });

  test("SOL-013: does not flag structs with no mint account in scope", () => {
    const src = `
      #[derive(Accounts)]
      pub struct Swap<'info> {
        #[account(mut)]
        pub user_token_a: Account<'info, TokenAccount>,
        #[account(mut)]
        pub vault_a: Account<'info, TokenAccount>,
      }
    `;
    const findings = ruleById("SOL-013").check(src, "test.rs");
    expect(findings.length).toBe(0);
  });
});
