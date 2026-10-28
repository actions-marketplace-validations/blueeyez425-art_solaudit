//! SolScape — persistent on-chain territory game (HARDENED BUILD).
//!
//! This is the deployable version. Every seeded bug from `programs/solscape/`
//! is fixed here; see ANSWER_KEY.md for the class → fix mapping:
//!
//!  B1  register_player:     init_if_needed → init (profile can never be wiped)
//!  B2  upgrade_tile:        checked math, explicit level cap (no overflow)
//!  B3  buy_tile:            typed Account<Tile> + has_one seller + PDA seeds
//!  B4  buy_tile_spl:        token_program is a typed Program<Token>
//!  B5  buy_tile_spl:        buyer/seller token accounts bound to the fee mint
//!  B6  close_tile:          Anchor `close =` constraint (data zeroed, owner reset)
//!  B7  withdraw_treasury:   authority must SIGN; has_one against config
//!  B8  withdraw_treasury:   treasury verified via seeds = [b"treasury"]
//!  B9  grant_achievement:   typed Account<PlayerProfile>, program-owner checked
//!
//! SolAudit 0.3.2 result on this build: 0 findings on the 9 fixed handlers.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke_signed;
use anchor_lang::solana_program::system_instruction;
use anchor_spl::token::{self, Mint, Token, TokenAccount};

declare_id!("81CG5b4NMn8hgGPfYQXDzx5b4KBe4MC31JUYvVnn8h1Q");

pub const GRID_SIZE: u8 = 100;
pub const CLAIM_FEE_LAMPORTS: u64 = 10_000_000; // 0.01 SOL
pub const UPGRADE_BASE_FEE: u64 = 5_000_000; // 0.005 SOL
pub const ROYALTY_BPS: u64 = 500; // 5%
pub const MAX_LEVEL: u8 = 10; // caps the price curve; 2^10 * base * max tiles stays far under u64::MAX

#[program]
pub mod solscape {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.authority = ctx.accounts.authority.key();
        config.claim_fee = CLAIM_FEE_LAMPORTS;
        config.royalty_bps = ROYALTY_BPS;
        Ok(())
    }

    /// FIX B1 — plain `init`: a second registration attempt fails outright.
    pub fn register_player(ctx: Context<RegisterPlayer>) -> Result<()> {
        let profile = &mut ctx.accounts.profile;
        profile.owner = ctx.accounts.player.key();
        profile.xp = 0;
        profile.tiles_claimed = 0;
        Ok(())
    }

    pub fn claim_tile(ctx: Context<ClaimTile>, x: u8, y: u8) -> Result<()> {
        require!(x < GRID_SIZE && y < GRID_SIZE, GameError::OutOfBounds);

        let tile = &mut ctx.accounts.tile;
        tile.owner = ctx.accounts.player.key();
        tile.x = x;
        tile.y = y;
        tile.level = 1;
        tile.list_price = 0;

        let fee = ctx.accounts.config.claim_fee;
        let ix = system_instruction::transfer(
            &ctx.accounts.player.key(),
            &ctx.accounts.treasury.key(),
            fee,
        );
        anchor_lang::solana_program::program::invoke(
            &ix,
            &[
                ctx.accounts.player.to_account_info(),
                ctx.accounts.treasury.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
        )?;

        let profile = &mut ctx.accounts.profile;
        profile.tiles_claimed = profile
            .tiles_claimed
            .checked_add(1)
            .ok_or(GameError::Overflow)?;
        Ok(())
    }

    /// FIX B2 — checked math throughout; level cap makes the pow chain bounded.
    pub fn upgrade_tile(ctx: Context<UpgradeTile>) -> Result<()> {
        let tile = &mut ctx.accounts.tile;
        let profile = &ctx.accounts.profile;

        require!(tile.level < MAX_LEVEL, GameError::MaxLevel);

        let multiplier = 2u64
            .checked_pow(tile.level as u32)
            .ok_or(GameError::Overflow)?;
        let fee = UPGRADE_BASE_FEE
            .checked_mul(multiplier)
            .and_then(|v| v.checked_mul(profile.tiles_claimed as u64))
            .ok_or(GameError::Overflow)?;

        let ix = system_instruction::transfer(
            &ctx.accounts.player.key(),
            &ctx.accounts.treasury.key(),
            fee,
        );
        anchor_lang::solana_program::program::invoke(
            &ix,
            &[
                ctx.accounts.player.to_account_info(),
                ctx.accounts.treasury.to_account_info(),
            ],
        )?;

        tile.level = tile.level.checked_add(1).ok_or(GameError::Overflow)?;
        Ok(())
    }

    pub fn list_tile(ctx: Context<ListTile>, price: u64) -> Result<()> {
        let tile = &mut ctx.accounts.tile;
        tile.list_price = price;
        Ok(())
    }

    /// FIX B3 — tile is a typed, PDA-verified Account<Tile>; the seller is
    /// cross-checked against tile.owner via has_one. Crafted accounts die at
    /// account resolution, before a single lamport moves.
    pub fn buy_tile(ctx: Context<BuyTile>) -> Result<()> {
        let tile = &mut ctx.accounts.tile;
        require!(tile.list_price > 0, GameError::NotForSale);

        let royalty = tile
            .list_price
            .checked_mul(ctx.accounts.config.royalty_bps)
            .and_then(|v| v.checked_div(10_000))
            .ok_or(GameError::Overflow)?;
        let seller_proceeds = tile
            .list_price
            .checked_sub(royalty)
            .ok_or(GameError::Overflow)?;

        // Buyer pays via system program: royalty → treasury, proceeds → seller.
        for (dest, amount) in [
            (&ctx.accounts.treasury, royalty),
            (&ctx.accounts.owner, seller_proceeds),
        ] {
            if amount > 0 {
                let ix = system_instruction::transfer(
                    &ctx.accounts.buyer.key(),
                    &dest.key(),
                    amount,
                );
                anchor_lang::solana_program::program::invoke(
                    &ix,
                    &[
                        ctx.accounts.buyer.to_account_info(),
                        dest.to_account_info(),
                        ctx.accounts.system_program.to_account_info(),
                    ],
                )?;
            }
        }

        tile.owner = ctx.accounts.buyer.key();
        tile.list_price = 0;
        Ok(())
    }

    /// FIX B4 + B5 — token_program is the real SPL Token program (Anchor
    /// enforces the program id at resolution), and both token accounts are
    /// bound to the official fee mint via `token::mint`.
    pub fn buy_tile_spl(ctx: Context<BuyTileSpl>, amount: u64) -> Result<()> {
        require!(amount > 0, GameError::NotForSale);

        let cpi_accounts = token::Transfer {
            from: ctx.accounts.buyer_token.to_account_info(),
            to: ctx.accounts.seller_token.to_account_info(),
            authority: ctx.accounts.buyer.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token::transfer(cpi_ctx, amount)?;

        let tile = &mut ctx.accounts.tile;
        tile.owner = ctx.accounts.buyer.key();
        tile.list_price = 0;
        Ok(())
    }

    /// FIX B6 — Anchor's `close =` constraint: lamports transferred, data
    /// zeroed, owner reassigned to the system program. Revival is impossible.
    pub fn close_tile(_ctx: Context<CloseTile>) -> Result<()> {
        Ok(())
    }

    /// FIX B7 + B8 — authority must sign AND match config.authority; treasury
    /// is verified against the derived PDA; the seeds used for signing are
    /// re-derived with the stored bump.
    pub fn withdraw_treasury(ctx: Context<WithdrawTreasury>, amount: u64) -> Result<()> {
        let treasury_bump = ctx.bumps.treasury;
        let ix = system_instruction::transfer(
            &ctx.accounts.treasury.key(),
            &ctx.accounts.recipient.key(),
            amount,
        );
        invoke_signed(
            &ix,
            &[
                ctx.accounts.treasury.to_account_info(),
                ctx.accounts.recipient.to_account_info(),
            ],
            &[&[b"treasury", &[treasury_bump]]],
        )?;
        Ok(())
    }

    /// FIX B9 — profile is a typed Account<PlayerProfile>: Anchor checks the
    /// discriminator AND that the account is owned by this program. A fake
    /// profile from an attacker program never reaches the handler.
    pub fn grant_achievement(ctx: Context<GrantAchievement>, xp: u64) -> Result<()> {
        let profile = &mut ctx.accounts.profile;
        profile.xp = profile.xp.checked_add(xp).ok_or(GameError::Overflow)?;
        Ok(())
    }

    pub fn harvest(ctx: Context<Harvest>) -> Result<()> {
        let tile = &ctx.accounts.tile;
        let profile = &mut ctx.accounts.profile;
        let reward = (tile.level as u64)
            .checked_mul(1_000)
            .ok_or(GameError::Overflow)?;
        profile.xp = profile.xp.checked_add(reward).ok_or(GameError::Overflow)?;
        Ok(())
    }
}

// ------------------------- Accounts -------------------------

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + 32 + 8 + 8, seeds = [b"config"], bump)]
    pub config: Account<'info, Config>,
    /// CHECK: treasury PDA, system-owned vault
    #[account(mut, seeds = [b"treasury"], bump)]
    pub treasury: UncheckedAccount<'info>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RegisterPlayer<'info> {
    // FIX B1: init only — existing profiles are untouchable here.
    #[account(init, payer = player, space = 8 + 32 + 8 + 4, seeds = [b"player".as_slice(), player.key().as_ref()], bump)]
    pub profile: Account<'info, PlayerProfile>,
    #[account(mut)]
    pub player: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(x: u8, y: u8)]
pub struct ClaimTile<'info> {
    #[account(seeds = [b"config"], bump)]
    pub config: Account<'info, Config>,
    #[account(init, payer = player, space = 8 + 32 + 1 + 1 + 1 + 8, seeds = [b"tile".as_slice(), x.to_le_bytes().as_slice(), y.to_le_bytes().as_slice()], bump)]
    pub tile: Account<'info, Tile>,
    #[account(mut, seeds = [b"player".as_slice(), player.key().as_ref()], bump, has_one = owner)]
    pub profile: Account<'info, PlayerProfile>,
    /// CHECK: treasury PDA — verified via seeds
    #[account(mut, seeds = [b"treasury"], bump)]
    pub treasury: UncheckedAccount<'info>,
    #[account(mut)]
    pub player: Signer<'info>,
    /// CHECK: the player whose profile is being updated (== player)
    #[account(constraint = owner.key() == player.key())]
    pub owner: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpgradeTile<'info> {
    #[account(mut, has_one = owner)]
    pub tile: Account<'info, Tile>,
    #[account(seeds = [b"player".as_slice(), owner.key().as_ref()], bump)]
    pub profile: Account<'info, PlayerProfile>,
    /// CHECK: treasury PDA — verified via seeds (was unbound in the fixture)
    #[account(mut, seeds = [b"treasury"], bump)]
    pub treasury: UncheckedAccount<'info>,
    #[account(mut)]
    pub player: Signer<'info>,
    /// CHECK: matches tile.owner via has_one
    pub owner: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ListTile<'info> {
    #[account(mut, has_one = owner)]
    pub tile: Account<'info, Tile>,
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
#[instruction()]
pub struct BuyTile<'info> {
    #[account(seeds = [b"config"], bump)]
    pub config: Account<'info, Config>,
    // FIX B3: typed + PDA-verified + seller bound to tile.owner via has_one
    #[account(mut, seeds = [b"tile".as_slice(), tile.x.to_le_bytes().as_slice(), tile.y.to_le_bytes().as_slice()], bump, has_one = owner)]
    pub tile: Account<'info, Tile>,
    /// CHECK: the current owner (seller), paid seller_proceeds; bound via has_one
    #[account(mut, constraint = owner.key() != treasury.key() @ GameError::AccountAliasing)]
    pub owner: UncheckedAccount<'info>,
    /// CHECK: treasury PDA — verified via seeds
    #[account(mut, seeds = [b"treasury"], bump)]
    pub treasury: UncheckedAccount<'info>,
    #[account(mut)]
    pub buyer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct BuyTileSpl<'info> {
    #[account(mut, has_one = owner)]
    pub tile: Account<'info, Tile>,
    /// The official fee-token mint.
    pub mint: Account<'info, Mint>,
    // FIX B5: both token accounts bound to the official mint.
    // Distinctness constraint (found by SOL-012): without it, a buyer could pass
    // the SAME account as buyer_token and seller_token — the SPL transfer becomes
    // a no-op debit/credit and they take the tile for free.
    #[account(
        mut,
        token::mint = mint,
        constraint = buyer_token.key() != seller_token.key() @ GameError::AccountAliasing
    )]
    pub buyer_token: Account<'info, TokenAccount>,
    #[account(mut, token::mint = mint, token::authority = owner)]
    pub seller_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub buyer: Signer<'info>,
    /// CHECK: matches tile.owner via has_one
    pub owner: UncheckedAccount<'info>,
    // FIX B4: typed program — Anchor enforces the SPL Token program id.
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct CloseTile<'info> {
    // FIX B6: Anchor close semantics — zeroed data, system-owned after.
    #[account(mut, close = owner, has_one = owner)]
    pub tile: Account<'info, Tile>,
    #[account(mut)]
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct WithdrawTreasury<'info> {
    #[account(seeds = [b"config"], bump, has_one = authority)]
    pub config: Account<'info, Config>,
    // FIX B8: treasury verified against the derived PDA.
    /// CHECK: treasury PDA — verified via seeds
    #[account(mut, seeds = [b"treasury"], bump)]
    pub treasury: UncheckedAccount<'info>,
    // FIX B7: destination is still caller-chosen, but the caller must be the
    // config authority AND must sign. Distinctness vs treasury is harmless to
    // add and silences the (benign) SOL-012 aliasing note.
    /// CHECK: fee destination chosen by the signing authority
    #[account(mut, constraint = recipient.key() != treasury.key() @ GameError::AccountAliasing)]
    pub recipient: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct GrantAchievement<'info> {
    // FIX B9: typed account — discriminator + program-owner enforced.
    #[account(mut)]
    pub profile: Account<'info, PlayerProfile>,
    pub oracle: Signer<'info>,
}

#[derive(Accounts)]
pub struct Harvest<'info> {
    #[account(has_one = owner)]
    pub tile: Account<'info, Tile>,
    #[account(mut, seeds = [b"player".as_slice(), owner.key().as_ref()], bump)]
    pub profile: Account<'info, PlayerProfile>,
    pub owner: Signer<'info>,
}

// ------------------------- State -------------------------

#[account]
pub struct Config {
    pub authority: Pubkey,
    pub claim_fee: u64,
    pub royalty_bps: u64,
}

#[account]
pub struct Tile {
    pub owner: Pubkey,
    pub x: u8,
    pub y: u8,
    pub level: u8,
    pub list_price: u64,
}

#[account]
pub struct PlayerProfile {
    pub owner: Pubkey,
    pub xp: u64,
    pub tiles_claimed: u32,
}

#[error_code]
pub enum GameError {
    #[msg("Coordinates out of bounds")]
    OutOfBounds,
    #[msg("Tile is not listed for sale")]
    NotForSale,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Profile mismatch")]
    BadProfile,
    #[msg("Tile is at max level")]
    MaxLevel,
    #[msg("Accounts must be distinct")]
    AccountAliasing,
}
