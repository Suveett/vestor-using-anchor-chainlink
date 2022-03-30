use anchor_lang::prelude::*;
use anchor_lang::solana_program::system_program;
use anchor_lang::solana_program::{clock /* , pubkey :: {ParsePubkeyError} */};
use anchor_spl::token::{self, Mint, Token, TokenAccount, MintTo};
use chainlink_solana as chainlink;

declare_id!("4UdRaLosDf3eyifPjzZAbKfRzSasBFsvWHktYyeHpEPh");


pub fn available(
    ticket: &mut Box<Account<Ticket>>,
) -> u64 {
    if has_cliffed(ticket) {
        return unlocked(ticket).checked_sub(ticket.claimed).unwrap();
    } else {
        return 0;
    }
}


pub fn has_cliffed(
    ticket: &mut Box<Account<Ticket>>,
) -> bool {
    let clock = clock::Clock::get().unwrap();
    if ticket.cliff == 0 {
        return true;
    }

    return  clock.unix_timestamp as u64 > ticket.created_at.checked_add(
        ticket.cliff.checked_mul(
            86400
        ).unwrap()
    ).unwrap();
}


pub fn unlocked(
    ticket: &mut Box<Account<Ticket>>,
) -> u64 {
    let clock = clock::Clock::get().unwrap();
    
    let timelapsed = (clock.unix_timestamp as u64).checked_sub(ticket.created_at).unwrap();  
    let vesting_in_seconds = ticket.vesting.checked_mul(86400).unwrap();

    return timelapsed.checked_mul(ticket.amount).unwrap().checked_div(
        vesting_in_seconds as u64
    ).unwrap();
}


#[program]
pub mod vestor_using_anchor_chainlink_master {
    use super::*;
    pub fn initialize(ctx: Context<Initialize> , bump : u8) -> Result<()> {
        let vestor = &mut ctx.accounts.vestor;
        let authority = &mut ctx.accounts.authority;
        vestor.current_id = 1;
        vestor.bump = bump;
        vestor.authority = *authority.key;

        Ok(())
    }

    pub fn proxy_mint_to(ctx: Context<ProxyMintTo>, amount: u64) -> Result<()> {
        token::mint_to(ctx.accounts.into(), amount);
        Ok(())
    }


    pub fn create(ctx: Context<Create>, beneficiary: Pubkey, cliff: u64, vesting: u64, amount: u64, irrevocable: bool) -> Result<()> {
        let vestor = &mut ctx.accounts.vestor;
        let clock = clock::Clock::get().unwrap();

        if amount == 0 {
            return Err(ErrorCode::AmountMustBeGreaterThanZero.into());
        } if vesting < cliff {
            return Err(ErrorCode::VestingPeriodShouldBeEqualOrLongerThanCliff.into());
        } 

         // Transfer tokens to vault.
         {
            let cpi_ctx = CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.grantor_token_vault.to_account_info(),
                    to: ctx.accounts.token_vault.to_account_info(),
                    authority: ctx.accounts.grantor.to_account_info(), //todo use user account as signer
                },
            );
            token::transfer(cpi_ctx, amount)?;
        }

        vestor.current_id += 1;
        let ticket = &mut ctx.accounts.ticket;
        ticket.token_mint = ctx.accounts.token_mint.key();
        ticket.token_vault = ctx.accounts.token_vault.key();
        ticket.grantor = ctx.accounts.grantor.key();
        ticket.beneficiary = beneficiary;
        ticket.cliff = cliff;
        ticket.vesting = vesting;
        ticket.amount = amount;
        ticket.balance = amount;
        ticket.created_at = clock.unix_timestamp as u64;
        ticket.irrevocable = irrevocable;
        ticket.is_revoked = false;

        Ok(())
    }


    pub fn claim(ctx: Context<Claim>) -> Result<()> {
        let vestor = &mut ctx.accounts.vestor;
        let ticket = &mut ctx.accounts.ticket;
        let clock = clock::Clock::get().unwrap();

        if ticket.is_revoked == true {
            return Err(ErrorCode::TicketRevoked.into());
        }

        let sol_round = chainlink::latest_round_data(
            ctx.accounts.chainlink_program.to_account_info(),
            ctx.accounts.chainlink_sol_feed.to_account_info(),
        )?;

        let sol_description = chainlink::description(
            ctx.accounts.chainlink_program.to_account_info(),
            ctx.accounts.chainlink_sol_feed.to_account_info(),
        )?;

        let sol_decimals = chainlink::decimals(
            ctx.accounts.chainlink_program.to_account_info(),
            ctx.accounts.chainlink_sol_feed.to_account_info(),
        )?;

        // Set the account value
        let value_of_sol: &mut Account<Value> = &mut ctx.accounts.value;
        value_of_sol.value= sol_round.answer;
        value_of_sol.decimals=u32::from(sol_decimals);

        // Also print the SOL value to the program output
        let value_print_sol = Value::new(sol_round.answer, u32::from(sol_decimals));
        msg!("{} price is {}", sol_description, value_print_sol);


        let eth_round = chainlink::latest_round_data(
            ctx.accounts.chainlink_program.to_account_info(),
            ctx.accounts.chainlink_eth_feed.to_account_info(),
        )?;

        let eth_description = chainlink::description(
            ctx.accounts.chainlink_program.to_account_info(),
            ctx.accounts.chainlink_eth_feed.to_account_info(),
        )?;

        let eth_decimals = chainlink::decimals(
            ctx.accounts.chainlink_program.to_account_info(),
            ctx.accounts.chainlink_eth_feed.to_account_info(),
        )?;

        // Set the account value
        let value_of_eth: &mut Account<Value> = &mut ctx.accounts.value;
        value_of_eth.value= eth_round.answer;
        value_of_eth.decimals=u32::from(eth_decimals);

        // Also print the ETH value to the program output
        let value_print_eth = Value::new(eth_round.answer, u32::from(eth_decimals));
        msg!("{} price is {}", eth_description, value_print_eth);

        let now = clock.unix_timestamp as u64;

        //Lucky combination of 0 claims + randomness of Time + condition of SOL Price having crossed ETH Price, 
        // Now all Vestors can claim and sell their Tokens as its Merry Christmas Time for the SOL Ecosystem..
        if now % 2 == 0  && ticket.claimed == 0 && value_print_sol.value > value_print_eth.value 
            {
                let amount = ticket.balance;

                // Transfer.
                {
                    let seeds = &[vestor.to_account_info().key.as_ref(), &[vestor.bump]];
                    let signer = &[&seeds[..]];

                    let cpi_ctx = CpiContext::new_with_signer(
                        ctx.accounts.token_program.to_account_info(),
                        token::Transfer {
                            from: ctx.accounts.token_vault.to_account_info(),
                            to: ctx.accounts.beneficiary_token_vault.to_account_info(),
                            authority: ctx.accounts.signer.to_account_info(), 
                        },
                        signer
                    );
                    token::transfer(cpi_ctx, amount)?;
                }

                ticket.claimed += amount;
                ticket.balance -= amount;
                ticket.last_claimed_at = clock.unix_timestamp as u64;
                ticket.num_claims += 1;

            }
        else 
            {
                let amount = available(ticket);


                // Transfer.
                {
                    let seeds = &[vestor.to_account_info().key.as_ref(), &[vestor.bump]];
                    let signer = &[&seeds[..]];

                    let cpi_ctx = CpiContext::new_with_signer(
                        ctx.accounts.token_program.to_account_info(),
                        token::Transfer {
                            from: ctx.accounts.token_vault.to_account_info(),
                            to: ctx.accounts.beneficiary_token_vault.to_account_info(),
                            authority: ctx.accounts.signer.to_account_info(), 
                        },
                        signer
                    );
                    token::transfer(cpi_ctx, amount)?;
                }

                ticket.claimed += amount;
                ticket.balance -= amount;
                ticket.last_claimed_at = clock.unix_timestamp as u64;
                ticket.num_claims += 1;
            }
        
       

        Ok(())
    }


    pub fn revoke(ctx: Context<Revoke>) -> Result<()> {
        let vestor = &mut ctx.accounts.vestor;
        let ticket = &mut ctx.accounts.ticket;
        let _clock = clock::Clock::get().unwrap();

        if ticket.is_revoked == true {
            return Err(ErrorCode::TicketRevoked.into());
        } 

 
        if ticket.irrevocable == true {
            return Err(ErrorCode::TicketIrrevocable.into());
        }

        // Transfer.
        {
            let seeds = &[vestor.to_account_info().key.as_ref(), &[vestor.bump]];
            let signer = &[&seeds[..]];

            let cpi_ctx = CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.token_vault.to_account_info(),
                    to: ctx.accounts.grantor_token_vault.to_account_info(),
                    authority: ctx.accounts.signer.to_account_info(), 
                },
                signer
            );
            token::transfer(cpi_ctx, ticket.balance)?;
        }

        ticket.is_revoked = true;
        ticket.balance = 0;

        Ok(())
    }

  


}


#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, 
        seeds = [b"vestor".as_ref(), 
        authority.key().as_ref()], 
        bump, 
        payer = authority, 
        space = 8 + 8)
    ]
    pub vestor: Account<'info, Vestor>, //Vestor is the PDA from whose keys the Ticket 'data account' and 'signer' is derived from
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}



#[derive(Accounts)]
pub struct Create<'info> {
    // Total 9 accounts used in 'Create'
    #[account(mut)]
    pub vestor: Account<'info, Vestor>,

    #[account(
        init_if_needed,
        payer = grantor,
        seeds = [
            vestor.to_account_info().key().as_ref(),
            vestor.current_id.to_string().as_ref(),
        ],
        bump
    )]
    pub ticket: Box<Account<'info, Ticket>>, //Data account derived from vestor keys and current_id

    pub token_mint: Box<Account<'info, Mint>>,

    #[account(
        constraint = token_vault.mint == token_mint.key(),
        constraint = token_vault.owner == signer.key(),
    )]
    pub token_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        constraint = grantor_token_vault.mint == token_mint.key(),
        constraint = grantor_token_vault.owner == grantor.key(),
    )]
    pub grantor_token_vault: Box<Account<'info, TokenAccount>>,

    /// CHECK: This Unchecked 'signer PDA' is not dangerous because this signer PDA is the same PDA on 
    /// whose key.as_ref() the token_vault PDA is derived from (See  => constraint = token_vault.owner == signer.key()
    /// and the funds are finally transferred to this signer PDA's token_vault PDA at the time of this 'transfer tx'.
    #[account(
        seeds = [
            vestor.to_account_info().key.as_ref()
        ],
        bump = vestor.bump,
    )]  
    pub signer: UncheckedAccount<'info>, // another PDA derived from vestor and this PDA signs transfer tx's in 'claim' and 'revoke' fns

    #[account(mut)]
    pub grantor: Signer<'info>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
}



#[derive(Accounts)]
pub struct Claim<'info> {  
    // Total 13 accounts used for 'Claim'
    #[account(mut)]
    pub vestor: Account<'info, Vestor>,

    #[account(
        mut,
        has_one = beneficiary,
        has_one = token_mint,
        has_one = token_vault,
        constraint = ticket.balance > 0,
        constraint = ticket.amount > 0,
    )]
    pub ticket: Box<Account<'info, Ticket>>,

    pub token_mint: Box<Account<'info, Mint>>,

    #[account(
        constraint = token_vault.mint == token_mint.key(),
        constraint = token_vault.owner == signer.key(),
    )]
    pub token_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        constraint = token_vault.mint == token_mint.key(),
        constraint = token_vault.owner == beneficiary.key(),
    )]
    pub beneficiary_token_vault: Box<Account<'info, TokenAccount>>,

    /// CHECK: The Unchecked Account 'signer PDA' is not dangerous because
    /// its seeds + bump are used to sign this 'transfer' tx in the 'claim' function.
    /// Also, Anchor checks that this 'signer PDA' is derived from vestor.to_account_info().key.as_ref() + bump.
    /// and the 'vestor pda' itself is generated using bump(nonce) + seeds of the
    /// Client 
    #[account(
        seeds = [
            vestor.to_account_info().key.as_ref()
        ],
        bump = vestor.bump,
    )]
    pub signer: UncheckedAccount<'info>,

    #[account(mut)]
    pub beneficiary: Signer<'info>,


    #[account(init, payer = beneficiary, space = 100)]
    pub value: Account<'info, Value>,

    ///CHECK : This account just reads the Sol Price from SOLANA_FEED ADDRESS && which arrived from the Chainlink Program
    pub chainlink_sol_feed: AccountInfo<'info>,

    ///CHECK : This account just reads the ETH Price from ETHEREUM_FEED ADDRESS && which arrived from the Chainlink Program
    pub chainlink_eth_feed: AccountInfo<'info>,

    /// CHECK : This is the Chainlink program's account
    pub chainlink_program: AccountInfo<'info>,

     /// CHECK : System Program address is already defined
     #[account(address = system_program::ID)]
    pub system_program: AccountInfo<'info>,

    //pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
}



#[derive(Accounts)]
pub struct Revoke<'info> {
    //Total 8 accounts used for Revoke
    #[account(mut)]
    pub vestor: Account<'info, Vestor>,

    #[account(
        mut,
        has_one = grantor,
        has_one = token_mint,
        has_one = token_vault,
        constraint = ticket.balance > 0,
    )]
    pub ticket: Box<Account<'info, Ticket>>,

    pub token_mint: Box<Account<'info, Mint>>,

    #[account(
        constraint = token_vault.mint == token_mint.key(),
        constraint = token_vault.owner == signer.key(),
    )]
    pub token_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        constraint = token_vault.mint == token_mint.key(),
        constraint = token_vault.owner == grantor.key(),
    )]
    pub grantor_token_vault: Box<Account<'info, TokenAccount>>,

   /// CHECK: The Unchecked Account 'signer PDA' is not dangerous because
    /// its seeds + bump are used to sign this 'transfer' tx in the 'revoke' function.
    /// Also, Anchor checks that this 'signer PDA' is derived from vestor.to_account_info().key.as_ref() + bump.
    /// and the 'vestor pda' itself was generated using bump(nonce) of the
    /// Beneficiary whose tokens are now being revoked. 
    #[account(
        seeds = [
            vestor.to_account_info().key.as_ref()
        ],
        bump = vestor.bump,
    )]
    pub signer: UncheckedAccount<'info>,

    #[account(mut)]
    pub grantor: Signer<'info>,

    pub token_program: Program<'info, Token>,
}


#[derive(Accounts)]
pub struct ProxyMintTo<'info> {

    /// CHECK :  Signer who is authorised
    #[account(signer)]
    pub authority: AccountInfo<'info>, 

    /// CHECK : the Mint account address
    #[account(mut)]
    pub mint: AccountInfo<'info>, 

    ///CHECK : This is the Token Account to whom the minted tokens are MINTED TO. 
    #[account(mut)]
    pub to: AccountInfo<'info>, 

    ///CHECK : This is not unsafe because this is the TokenProgram.programId which has to be declared anyways.
    pub token_program: AccountInfo<'info>, 
}



#[account]
pub struct Vestor {
    pub current_id: u64,
    pub bump: u8, 
    pub authority : Pubkey,
}


#[account]
#[derive(Default)]
pub struct Ticket {
    pub token_mint: Pubkey,
    pub token_vault: Pubkey,
    pub grantor: Pubkey,
    pub beneficiary: Pubkey,
    pub cliff: u64, 
    pub vesting: u64,
    pub amount: u64,
    pub claimed: u64,
    pub balance: u64,
    pub created_at: u64,
    pub last_claimed_at: u64,
    pub num_claims: u64,
    pub irrevocable: bool,
    pub is_revoked: bool,
    pub revoked_at: u64,
}


#[account]
pub struct Value {
    pub value: i128,
    pub decimals: u32,
}

impl Value {
    pub fn new(value: i128, decimals: u32) -> Self {
        Value { value, decimals }
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut scaled_val = self.value.to_string();
        if scaled_val.len() <= self.decimals as usize {
            scaled_val.insert_str(
                0,
                &vec!["0"; self.decimals as usize - scaled_val.len()].join(""),
            );
            scaled_val.insert_str(0, "0.");
        } else {
            scaled_val.insert(scaled_val.len() - self.decimals as usize, '.');
        }
        f.write_str(&scaled_val)
    }
}




impl<'a, 'b, 'c, 'info> From<&mut ProxyMintTo<'info>>
    for CpiContext<'a, 'b, 'c, 'info, MintTo<'info>>
{
    fn from(accounts: &mut ProxyMintTo<'info>) -> CpiContext<'a, 'b, 'c, 'info, MintTo<'info>> {
        let cpi_accounts = MintTo {
            authority: accounts.authority.clone(),
            mint: accounts.mint.clone(),
            to: accounts.to.clone(),
        };
        let cpi_program = accounts.token_program.clone();
        CpiContext::new(cpi_program, cpi_accounts)
    }
}

#[error_code]
pub enum ErrorCode {
    #[msg("Amount must be greater than zero.")]
    AmountMustBeGreaterThanZero,
    #[msg("Vesting period should be equal or longer to the cliff")]
    VestingPeriodShouldBeEqualOrLongerThanCliff,
    #[msg("Ticket has been revoked")]
    TicketRevoked,
    #[msg("Ticket is irrevocable")]
    TicketIrrevocable,
}

