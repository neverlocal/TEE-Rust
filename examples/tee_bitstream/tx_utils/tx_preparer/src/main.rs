use ethers::{
    core::types::{
        transaction::eip2718::TypedTransaction,
        Address,
        Eip1559TransactionRequest,
        U256,
    },
};

use libsecp256k1::{
    Message,
};

use std::str::FromStr;

fn main() {

    // Format a simple transaction
    // ================================
    // We will send 0.01 ETH to the zero address.
    // Note: ETH amounts are in Wei (1 ETH = 10^18 Wei).
    let from_address = Address:: from_str("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap();
    let to_address = Address::zero();
    let value = U256::from(10_000_000_000_000_000u64);

    // We'll use the modern EIP-1559 transaction type.
    let tx: TypedTransaction = Eip1559TransactionRequest::new()
        .from(from_address)
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
   
    let tx_hash = tx.sighash();
    println!("Hash: {:?}", tx_hash);
    println!("---------------------------------");

    let message =  Message::parse(&tx_hash.to_fixed_bytes());
    println!("Message: {:x?}", message);
    println!("---------------------------------");

}