
const anchor = require('@project-serum/anchor');
const assert = require("assert");
const { Buffer } = require('buffer');


const TokenInstructions = require("@project-serum/serum").TokenInstructions;
const serumCmn = require("@project-serum/common");
const TOKEN_PROGRAM_ID = new anchor.web3.PublicKey(
  TokenInstructions.TOKEN_PROGRAM_ID.toString()
);

const CHAINLINK_PROGRAM_ID = "CaH12fwNTKJAG8PxEvo9R96Zc2j8qNHZaFj8ZW49yZNT";
// SOL/USD feed account
const SOLANA_FEED = "EdWr4ww1Dq82vPe8GFjjcVPo2Qno3Nhn6baCgM3dCy28";
// ETH/USD feed account
const ETHEREUM_FEED = "5zxs8888az8dgB5KauGEFoPuMANtrKtkpFiFRmo3cSa9";
const DIVISOR = 100000000;



describe("vestor-using-anchor-chainlink-master", () => {
  // Specify provider environment. 
  const provider = anchor.Provider.env();
  //Set provider.
  anchor.setProvider(provider);

  const program = anchor.workspace.VestorUsingAnchorChainlinkMaster;

  let mint = null;
  let tokenVault = null;
  let grantorTokenVault = null;
  let beneficiary = anchor.web3.Keypair.generate();
 

  it("Initialize the test state and Creates All Accounts", async () => {

   // Discover/find the 'vestor' publicKey based on 'seeds'
   const [vestor, bump] = await anchor.web3.PublicKey.findProgramAddress(
    [Buffer.from("vestor"), provider.wallet.publicKey.toBuffer()],
    program.programId
  );
  console.log("Vestor Account Created : ", vestor);

    await program.rpc.initialize(new anchor.BN(bump),{
      accounts: {
        vestor: vestor,
        authority: provider.wallet.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      },
      
    });

    
    const vestorAccount = await program.account.vestor.fetch(vestor);
    console.log("Vestor Account Created : ", vestorAccount);
    const currentId = vestorAccount.currentId;

    
    // Discover/find the 'ticket' publicKey based on vestor.key.as_ref()
    const [ticket, _nonce] = await anchor.web3.PublicKey.findProgramAddress(
      [Buffer.from(anchor.utils.bytes.utf8.encode(vestor)), Buffer.from(currentId.toString())],
      program.programId
    );
    
    // Discover the signer publicKey based on vestor.key.as_ref()
    // and based on its constraint = bump == vestor.bump
    const [signer, _bump = bump] = await anchor.web3.PublicKey.findProgramAddress(
      [Buffer.from(anchor.utils.bytes.utf8.encode(vestor))],
      program.programId
    );

  
    mint = await createMint(provider);
    console.log("Mint Info : ", await getMintInfo(provider, mint));

    grantorTokenVault = await createTokenAccount(provider, mint, provider.wallet.publicKey); 
    console.log("Grantor Token vault created : ", await getTokenAccount(provider, grantorTokenVault));

    tokenVault = await createTokenAccount(provider, mint, signer); 
    console.log("Token vault created : ", await getTokenAccount(provider, tokenVault));

  
    const res_mint = await program.rpc.proxyMintTo(new anchor.BN(10000e8), {
      accounts: {
        authority: provider.wallet.publicKey,
        mint : mint, 
        to: grantorTokenVault,
        tokenProgram: TokenInstructions.TOKEN_PROGRAM_ID,
      },
    });

    console.log("Minted 10000 tokens to Grantor Token Vault, here's the signature : ",res_mint);

    //Now lets register the Ticket Account with a specified vesting period
    await program.rpc.create(
      beneficiary.publicKey,
      new anchor.BN(50),
      new anchor.BN(65),
      new anchor.BN(5000),
      false, {
      accounts: {
        vestor: vestor,
        ticket: ticket,
        tokenMint: mint,
        tokenVault: tokenVault,
        grantorTokenVault: grantorTokenVault,
        signer: signer,
        grantor: provider.wallet.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
        tokenProgram: TOKEN_PROGRAM_ID,

      }
    });
  
    
    const ticketAccount = await program.account.ticket.fetch(ticket);
    console.log("Ticket Account Created :", ticketAccount);
    console.log("Ticket Account PublicKey : ", ticketAccount.key.toString());

  });




});


async function createMint(provider, authority) {
  if (authority === undefined) { 
    authority = provider.wallet.publicKey;
  }
  const mint = anchor.web3.Keypair.generate();
  const instructions = await createMintInstructions(
    provider,
    authority,
    mint.publicKey
  );

  const tx = new anchor.web3.Transaction();
  tx.add(...instructions);

  await provider.send(tx, [mint]);

  return mint.publicKey;
}

async function createMintInstructions(provider, authority, mint) {
  let instructions = [
    anchor.web3.SystemProgram.createAccount({
      fromPubkey: provider.wallet.publicKey,
      newAccountPubkey: mint,
      space: 82,
      lamports: await provider.connection.getMinimumBalanceForRentExemption(82),
      programId: TOKEN_PROGRAM_ID,
    }),
    TokenInstructions.initializeMint({
      mint : mint,//
      decimals: 0,
      mintAuthority: authority,
    }),
  ];
  return instructions;
}


async function createTokenAccount(provider, mint, owner) {
  const vault = anchor.web3.Keypair.generate();
  const tx = new anchor.web3.Transaction();
  tx.add(
    ...(await createTokenAccountInstrs(provider, vault.publicKey, mint, owner))
  );
  await provider.send(tx, [vault]);
  return vault.publicKey;
}

async function createTokenAccountInstrs(
  provider,
  newAccountPubkey,
  mint,
  owner,
  lamports
) {
  if (lamports === undefined) {
    lamports = await provider.connection.getMinimumBalanceForRentExemption(165);
  }
  let instructions = [
    anchor.web3.SystemProgram.createAccount({
      fromPubkey: provider.wallet.publicKey,
      newAccountPubkey,
      space: 165,
      lamports,
      programId: TOKEN_PROGRAM_ID,
    }),
    TokenInstructions.initializeAccount({
      account: newAccountPubkey,
      mint: mint,
      owner: owner,
    }),
  ];
  return instructions;
}


async function getTokenAccount(provider, addr) {
  return await serumCmn.getTokenAccount(provider, addr);
}

async function getMintInfo(provider, mintAddr) {
  return await serumCmn.getMintInfo(provider, mintAddr);
}


/*const anchor = require('@project-serum/anchor');
const assert = require("assert");
const { Buffer } = require('buffer');
//const {VestorUsingAnchorChainlinkMaster} = require("../target/types/vestor_using_anchor_chainlink_master")
const { mintTo, transfer, getOrCreateAssociatedTokenAccount, mintToChecked, getMint, MINT_SIZE, createInitializeMintInstruction, getAssociatedTokenAddress, createAssociatedTokenAccountInstruction, getAccount, createMintToCheckedInstruction } = require("@solana/spl-token");
const serumCmn = require("@project-serum/common");
const TokenInstructions = require("@project-serum/serum").TokenInstructions;

const TOKEN_PROGRAM_ID = new anchor.web3.PublicKey(
  TokenInstructions.TOKEN_PROGRAM_ID.toString()
);


const CHAINLINK_PROGRAM_ID = "CaH12fwNTKJAG8PxEvo9R96Zc2j8qNHZaFj8ZW49yZNT";
// SOL/USD feed account
const SOLANA_FEED = "EdWr4ww1Dq82vPe8GFjjcVPo2Qno3Nhn6baCgM3dCy28";
// ETH/USD feed account
const ETHEREUM_FEED = "5zxs8888az8dgB5KauGEFoPuMANtrKtkpFiFRmo3cSa9";
const DIVISOR = 100000000;

const programVestor = anchor.workspace.VestorUsingAnchorChainlinkMaster;

// Specify provider environment. 
const provider = anchor.Provider.env();
//Set provider.
anchor.setProvider(provider);


describe("vestor-using-anchor-chainlink-master", () => {

  let mint = null;
  let grantorTokenVault = null;
  let tokenVault = null;
  let beneficiary = anchor.web3.Keypair.generate();




  it("Initialize the test state and vestor account", async () => {

   console.log("Starting 'Initialization test' !!");
    // Create & Initialize Mint Account and also the Token Accounts , i.e. grantor_token_vault & token_vault
    mint = await createMint(provider);
    grantorTokenVault = await createTokenAccount(provider, mint, programVestor.provider.wallet.publicKey);

    let [vestor, bump] = await anchor.web3.PublicKey.findProgramAddress(
      [Buffer.from("vestor"), programVestor.provider.wallet.publicKey.toBuffer()],
      programVestor.programId
    );


    let newTx = new anchor.web3.Transaction().add(
      createMintToCheckedInstruction(
        mint, // mint
        grantorTokenVault, // receiver (should be a token account)
        programVestor.provider.wallet.publicKey, // mint authority
        10000e8, // amount. if your decimals is 8, you mint 10^8 for 1 token.
        8 // decimals
      )
    )

    const resMint = await programVestor.provider.send(newTx);

    console.log("MINT TX", resMint);

    const tx = await programVestor.rpc.initialize({
      accounts: {
        vestor: vestor,
        user: provider.wallet.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      },
    })

    const account = await programVestor.account.vestor.fetch(vestor);
    console.log("Vestor Account : ", account);

  });



  it("Can create Vesting", async () => {

    console.log("Starting 'Create Vesting' test !!");
    // Create & Initialize Mint and Create Token Accounts : grantor_token_vault & token_vault
    mint = await createMint(provider);
    grantorTokenVault = await createTokenAccount(provider, mint, programVestor.provider.wallet.publicKey);


    let [vestor, bump] = await anchor.web3.PublicKey.findProgramAddress(
      [Buffer.from("vestor"), programVestor.provider.wallet.publicKey.toBuffer()],
      programVestor.programId
    );
    const [ticket, _nonce] = await anchor.web3.PublicKey.findProgramAddress(
      [Buffer.from(anchor.utils.bytes.utf8.encode(vestor)), Buffer.from(await programVestor.account.vestor.currentId.fetch(vestor))],
      programVestor.programId
    );

    const [signer, _bump_seed] = await anchor.web3.PublicKey.findProgramAddress(
      [Buffer.from(vestor), bump],
      programVestor.programId
    );
    tokenVault = await createTokenAccount(provider, mint, signer);

    const tx = await programVestor.rpc.create(
      beneficiary.publicKey,
      new anchor.BN(50),
      new anchor.BN(65),
      new anchor.BN(5000),
      false, {
      accounts: {
        vestor: vestor,
        ticket: ticket,
        tokenMint: mint,
        tokenVault: tokenVault,
        grantorTokenVault: grantorTokenVault,
        signer: signer,
        grantor: programVestor.provider.wallet.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
        tokenProgram: TokenInstructions.TOKEN_PROGRAM_ID,

      }


    });
    console.log("Your Create Vesting Transaction's signature :", tx);
    console.log("Ticket Account Created : ", ticket.toString());
  });


  it("Can claim its tokens", async () => {

    // add you test here
  });


  it("Can revoke tokens", async () => {

    // add you test here
  });



});


async function getTokenAccount(provider, addr) {
  return await serumCmn.getTokenAccount(provider, addr);
}

async function getMintInfo(provider, mintAddr) {
  return await serumCmn.getMintInfo(provider, mintAddr);
}

async function createMint(provider, authority) {
  if (authority === undefined) {
    authority = provider.wallet.publicKey;
  }
  const mint = anchor.web3.Keypair.generate();
  const instructions = await createMintInstructions(
    provider,
    authority,
    mint.publicKey
  );

  const tx = new anchor.web3.Transaction();
  tx.add(...instructions);

  await provider.send(tx, [mint]);

  return mint.publicKey;
}

async function createMintInstructions(provider, authority, mint) {
  let instructions = [
    anchor.web3.SystemProgram.createAccount({
      fromPubkey: provider.wallet.publicKey,
      newAccountPubkey: mint,
      space: 82,
      lamports: await provider.connection.getMinimumBalanceForRentExemption(82),
      programId: TOKEN_PROGRAM_ID,
    }),
    TokenInstructions.initializeMint({
      mint: mint,//
      decimals: 8,
      mintAuthority: authority,
    }),
  ];
  return instructions;
}

async function createTokenAccount(provider, mint, owner) {
  const vault = anchor.web3.Keypair.generate();
  const tx = new anchor.web3.Transaction();
  tx.add(
    ...(await createTokenAccountInstrs(provider, vault.publicKey, mint, owner))
  );
  await provider.send(tx, [vault]);
  return vault.publicKey;
}

async function createTokenAccountInstrs(
  provider,
  newAccountPubkey,
  mint,
  owner,
  lamports
) {
  if (lamports === undefined) {
    lamports = await provider.connection.getMinimumBalanceForRentExemption(165);
  }
  let instructions = [
    anchor.web3.SystemProgram.createAccount({
      fromPubkey: provider.wallet.publicKey,
      newAccountPubkey,
      space: 165,
      lamports,
      programId: TOKEN_PROGRAM_ID,
    }),
    TokenInstructions.initializeAccount({
      account: newAccountPubkey,
      mint: mint,
      owner: owner,
    }),
  ];
  return instructions;
}
*/
