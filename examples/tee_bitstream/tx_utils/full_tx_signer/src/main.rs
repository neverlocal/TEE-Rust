use ethers::{
    core::types::{
        transaction::eip2718::TypedTransaction,
        Address,
        Eip1559TransactionRequest,
        Signature,
        U256,
    },
    signers::{
        LocalWallet,
        Signer
    },
};

use libsecp256k1::{
    Message,
    SecretKey,
    PublicKey,
};

use eyre::Result;

const SECRET_KEY: [u8;32] = [
    0xac,
    0x09,
    0x74,
    0xbe,
    0xc3,
    0x9a,
    0x17,
    0xe3,
    0x6b,
    0xa4,
    0xa6,
    0xb4,
    0xd2,
    0x38,
    0xff,
    0x94,
    0x4b,
    0xac,
    0xb4,
    0x78,
    0xcb,
    0xed,
    0x5e,
    0xfc,
    0xae,
    0x78,
    0x4d,
    0x7b,
    0xf4,
    0xf2,
    0xff,
    0x80,
];

// Use tokio for our async main function
#[tokio::main]
async fn main() -> Result<()> {
    
    let secret_key_no_prefix = hex::encode(SECRET_KEY);
    let secret_key = format!("0x{}", secret_key_no_prefix);

    println!("Secret key: {}", secret_key);

    let wallet = secret_key
        .parse::<LocalWallet>()?
        .with_chain_id(1u64); // 1 for Ethereum Mainnet, 1337 for local dev
    
    println!("Successfully initialized wallet.");
    println!("---------------------------------");

    // 2. Compute the corresponding wallet address
    // ===========================================
    let wallet_address: Address = wallet.address();
    println!("Wallet address: {:?}", wallet_address);
    println!("---------------------------------");

    // 3. Format a simple transaction
    // ================================
    // We will send 0.01 ETH to the zero address.
    // Note: ETH amounts are in Wei (1 ETH = 10^18 Wei).
    let to_address = Address::zero();
    let value = U256::from(10_000_000_000_000_000u64);

    // We'll use the modern EIP-1559 transaction type.
    let tx: TypedTransaction = Eip1559TransactionRequest::new()
        .to(to_address)
        .value(value)
        .nonce(0) // In a real app, you'd get this from an RPC provider
        .gas(21000) // Standard gas limit for a simple ETH transfer
        .max_fee_per_gas(U256::from(20_000_000_000u64)) // 20 Gwei
        .max_priority_fee_per_gas(U256::from(1_500_000_000u64)) // 1.5 Gwei
        .chain_id(1u64) // 1 for Ethereum Mainnet, 1337 for local dev
        .into(); // Convert to TypedTransaction

    println!("Formatted transaction:\n{:?}", tx);
    println!("---------------------------------");
   
    // 4. Sign the transaction
    // =========================

    let tx_hash = tx.sighash();
    println!("Hash: {:?}", tx_hash);

    let signature: Signature = wallet.sign_transaction(&tx).await?;
    println!("Successfully signed the transaction.");
    println!("Signature (r, s, v): {:?}", signature);
    println!("---------------------------------");

    // 5. Put it in a format that allows it to be broadcasted
    // ======================================================
    // This is the "raw transaction". It's the RLP-encoded, signed transaction.
    // This is what you would send to an Ethereum node via `eth_sendRawTransaction`.
    let raw_tx_bytes = tx.rlp_signed(&signature);
    let raw_tx_hex = format!("0x{}", hex::encode(&raw_tx_bytes));

    //println!("Raw transaction hash: {:?}", raw_tx_bytes.hash());
    println!("Raw transaction (for broadcasting):\n{}", raw_tx_hex);
    println!("---------------------------------");

    Ok(())
}