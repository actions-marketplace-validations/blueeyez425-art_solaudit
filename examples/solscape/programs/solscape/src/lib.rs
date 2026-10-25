//! SolScape — persistent on-chain territory game.
//!
//! ⚠️  INTENTIONALLY VULNERABLE TEST FIXTURE (v2) ⚠️
//! This build contains deliberately seeded vulnerabilities for benchmarking the
//! SolAudit scanner (see ANSWER_KEY.md). DO NOT DEPLOY. The hardened build lives
//! in `programs/solscape-fixed/` and is the only version that may ever be deployed.
//!
//! v2 realism fixes (disclosed in SCORECARD.md):
//!  - withdraw_treasury now uses invoke_signed (the genuinely exploitable shape)
//!  - close_tile leaves account data intact (genuine close-then-revive)
//!  - buy_tile_spl takes typed token accounts + a mint, with the CPI program id
//!    sourced from an unchecked account (textbook arbitrary-CPI shape)

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::solana_program::program::{invoke, invoke_signed};
use anchor_lang::solana_program::system_instruction;
use anchor_spl::token::{Mint, TokenAccount};

declare_id!("So1Scape11111111111111111111111111111111111");

pub const GRID_SIZE: u8 = 100;
pub const CLAIM_FEE_LAMPORTS: u64 = 10_000_000; // 0.01 SOL
pub const UPGRADE_BASE_FEE: u64 = 5_000_000; // 0.005 SOL
pub const ROYALTY_BPS: u64 = 500; // 5%

#[program]
pub mod solscape {
    use super::*;

    /// C1 — clean control: proper init, seeds, signer.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.authority = ctx.accounts.authority.key();
        config.claim_fee = CLAIM_FEE_LAMPORTS;
        config.royalty_bps = ROYALTY_BPS;
        Ok(())
    }

    /// B1 — SEEDED: init_if_needed lets anyone wipe an existing profile back to zero.
    pub fn register_player(ctx: Context<RegisterPlayer>) -> Result<()> {
        let profile = &mut ctx.accounts.profile;
        profile.owner = ctx.accounts.player.key();
        profile.xp = 0;
        profile.tiles_claimed = 0;
        Ok(())
    }

    /// C2 — clean control: PDA via seeds, Signer, explicit system-program CPI.
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
        invoke(
            &ix,
            &[
                ctx.accounts.player.to_account_info(),
                ctx.accounts.treasury.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
        )?;

        let profile = &mut ctx.accounts.profile;
        profile.tiles_claimed = profile.tiles_claimed.checked_add(1).unwrap();
        Ok(())
    }

    /// B2 — SEEDED: price curve overflows; at high level the fee wraps to ~zero.
    pub fn upgrade_tile(ctx: Context<UpgradeTile>) -> Result<()> {
        let tile = &mut ctx.accounts.tile;
        let profile = &ctx.accounts.profile;

        // fee = base * 2^level * tiles_owned  — unchecked pow/mul chain
        let fee = UPGRADE_BASE_FEE
            * 2u64.pow(tile.level as u32)
            * profile.tiles_claimed as u64;

        let ix = system_instruction::transfer(
            &ctx.accounts.player.key(),
            &ctx.accounts.treasury.key(),
            fee,
        );
        invoke(
            &ix,
            &[
                ctx.accounts.player.to_account_info(),
                ctx.accounts.treasury.to_account_info(),
            ],
        )?;

        tile.level = tile.level + 1;
        Ok(())
    }

    /// C3 — clean control: has_one, Signer, no CPI.
    pub fn list_tile(ctx: Context<ListTile>, price: u64) -> Result<()> {
        let tile = &mut ctx.accounts.tile;
        tile.list_price = price;
        Ok(())
    }

    /// B3 — SEEDED: tile is a raw account; price/seller are trusted from
    /// attacker-controllable bytes. Pass any crafted account as "tile".
    pub fn buy_tile(ctx: Context<BuyTile>) -> Result<()> {
        let tile_info = &ctx.accounts.tile;
        let data = tile_info.try_borrow_data()?;
        // layout: [disc(8) | owner(32) | x(1) | y(1) | level(1) | list_price(8)]
        let list_price = u64::from_le_bytes(data[43..51].try_into().unwrap());
        require!(list_price > 0, GameError::NotForSale);

        let royalty = list_price * ROYALTY_BPS / 10_000;
        let seller_proceeds = list_price - royalty;

        **ctx.accounts.buyer.try_borrow_mut_lamports()? -= list_price;
        **ctx.accounts.seller.try_borrow_mut_lamports()? += seller_proceeds;
        **ctx.accounts.treasury.try_borrow_mut_lamports()? += royalty;

        drop(data);
        let mut data = tile_info.try_borrow_mut_data()?;
        data[8..40].copy_from_slice(&ctx.accounts.buyer.key().to_bytes());
        Ok(())
    }

    /// B4 + B5 — SEEDED: the CPI program id comes from an UNCHECKED account
    /// (arbitrary CPI), and buyer_token is never bound to the expected mint
    /// (pay with worthless tokens — the Cashio class).
    pub fn buy_tile_spl(ctx: Context<BuyTileSpl>, amount: u64) -> Result<()> {
        let ix = spl_token_transfer(
            &ctx.accounts.token_program.key(),
            &ctx.accounts.buyer_token.key(),
            &ctx.accounts.seller_token.key(),
            &ctx.accounts.buyer.key(),
            amount,
        );
        invoke(
            &ix,
            &[
                ctx.accounts.buyer_token.to_account_info(),
                ctx.accounts.seller_token.to_account_info(),
                ctx.accounts.buyer.to_account_info(),
                ctx.accounts.token_program.to_account_info(),
            ],
        )?;

        let tile = &mut ctx.accounts.tile;
        tile.owner = ctx.accounts.buyer.key();
        tile.list_price = 0;
        Ok(())
    }

    /// B6 — SEEDED: lamports drained but data/discriminator left intact and owner
    /// not reassigned — the account can be re-funded and revived with stale state.
    pub fn close_tile(ctx: Context<CloseTile>) -> Result<()> {
        let tile_info = &ctx.accounts.tile;
        let dest = &ctx.accounts.owner;

        let lamports = tile_info.lamports();
        **tile_info.try_borrow_mut_lamports()? = 0;
        **dest.try_borrow_mut_lamports()? += lamports;
        Ok(())
    }

    /// B7 + B8 — SEEDED: the program PDA-signs the transfer (so the runtime needs
    /// no caller signature), `authority` is never required to sign, `recipient` is
    /// caller-chosen, and `treasury` is never verified against the derived PDA.
    /// Anyone can call this and drain the vault to themselves.
    pub fn withdraw_treasury(ctx: Context<WithdrawTreasury>, amount: u64, bump: u8) -> Result<()> {
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
            &[&[b"treasury", &[bump]]],
        )?;
        Ok(())
    }

    /// B9 — SEEDED: profile is a raw account with no owner check; a fake profile
    /// account owned by an attacker program passes straight through.
    pub fn grant_achievement(ctx: Context<GrantAchievement>, xp: u64) -> Result<()> {
        let profile_info = &ctx.accounts.profile;
        let mut data = profile_info.try_borrow_mut_data()?;
        // layout: [disc(8) | owner(32) | xp(8) | tiles_claimed(4)]
        let current = u64::from_le_bytes(data[40..48].try_into().unwrap());
        data[40..48].copy_from_slice(&(current + xp).to_le_bytes());
        Ok(())
    }

    /// C4 — clean control: checked math, has_one constraints.
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

fn spl_token_transfer(
    program_id: &Pubkey,
    from: &Pubkey,
    to: &Pubkey,
    authority: &Pubkey,
    amount: u64,
) -> Instruction {
    let mut data = vec![3u8];
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*from, false),
            AccountMeta::new(*to, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
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
    #[account(init_if_needed, payer = player, space = 8 + 32 + 8 + 4, seeds = [b"player", player.key().as_ref()], bump)]
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
    #[account(init, payer = player, space = 8 + 32 + 1 + 1 + 1 + 8, seeds = [b"tile", &[x], &[y]], bump)]
    pub tile: Account<'info, Tile>,
    #[account(mut, seeds = [b"player", player.key().as_ref()], bump)]
    pub profile: Account<'info, PlayerProfile>,
    /// CHECK: treasury PDA
    #[account(mut, seeds = [b"treasury"], bump)]
    pub treasury: UncheckedAccount<'info>,
    #[account(mut)]
    pub player: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpgradeTile<'info> {
    #[account(mut, has_one = owner)]
    pub tile: Account<'info, Tile>,
    #[account(seeds = [b"player", owner.key().as_ref()], bump)]
    pub profile: Account<'info, PlayerProfile>,
    /// CHECK: treasury PDA — SEEDED B8-adjacent: no seeds binding here either
    #[account(mut)]
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
pub struct BuyTile<'info> {
    /// CHECK: SEEDED B3 — raw account, no owner/discriminator validation
    #[account(mut)]
    pub tile: UncheckedAccount<'info>,
    /// CHECK: SEEDED B3 — seller paid without cross-checking against tile state
    #[account(mut)]
    pub seller: UncheckedAccount<'info>,
    /// CHECK: SEEDED — treasury never PDA-verified in this struct
    #[account(mut)]
    pub treasury: UncheckedAccount<'info>,
    #[account(mut)]
    pub buyer: Signer<'info>,
}

#[derive(Accounts)]
pub struct BuyTileSpl<'info> {
    #[account(mut, has_one = owner)]
    pub tile: Account<'info, Tile>,
    /// The official fee-token mint.
    pub mint: Account<'info, Mint>,
    /// SEEDED B5 — never bound to `mint` (token::mint = mint missing)
    #[account(mut)]
    pub buyer_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub seller_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub buyer: Signer<'info>,
    /// CHECK: matches tile.owner via has_one
    pub owner: UncheckedAccount<'info>,
    /// CHECK: SEEDED B4 — CPI program id sourced from this unchecked account
    pub token_program: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct CloseTile<'info> {
    /// CHECK: SEEDED B6 — manual close path
    #[account(mut)]
    pub tile: UncheckedAccount<'info>,
    #[account(mut)]
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct WithdrawTreasury<'info> {
    /// CHECK: SEEDED B8 — never verified against the derived treasury PDA
    #[account(mut)]
    pub treasury: UncheckedAccount<'info>,
    /// CHECK: SEEDED B7 — caller-chosen destination
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
    /// CHECK: SEEDED B7 — authority is never required to sign
    pub authority: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct GrantAchievement<'info> {
    /// CHECK: SEEDED B9 — raw profile account, no owner check
    #[account(mut)]
    pub profile: UncheckedAccount<'info>,
    pub oracle: Signer<'info>,
}

#[derive(Accounts)]
pub struct Harvest<'info> {
    #[account(has_one = owner)]
    pub tile: Account<'info, Tile>,
    #[account(mut, seeds = [b"player", owner.key().as_ref()], bump)]
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
}
