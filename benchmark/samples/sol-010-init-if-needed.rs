use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

// VULNERABLE: `init_if_needed` lets a pre-existing account flow through the
// same validation path as a freshly initialized one. With no PDA seeds/bump
// and no `has_one`/`constraint` binding the record to expected state, an
// attacker can pre-create or reuse account state the program assumes it
// initialized itself.
#[program]
pub mod registry {
    use super::*;

    pub fn register(ctx: Context<Register>) -> Result<()> {
        let record = &mut ctx.accounts.record;
        record.authority = ctx.accounts.authority.key();
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Register<'info> {
    // BUG: init_if_needed without seeds or additional constraints.
    #[account(init_if_needed, payer = authority, space = 8 + 32)]
    pub record: Account<'info, Record>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct Record {
    pub authority: Pubkey,
}
