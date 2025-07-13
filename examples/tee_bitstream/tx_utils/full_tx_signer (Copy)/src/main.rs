use ethers::{
    core::types::{
        transaction::eip2718::TypedTransaction,
        Address,
        Eip1559TransactionRequest,
        Signature,
        U256,
    },
};

use std::str::FromStr;

// ADD THE SIGNATURE DATA HERE
const R : [u8;32] = [126, 199, 157, 78, 202, 156, 20, 135, 21, 62, 148, 153, 220, 87, 68, 198, 13, 134, 17, 7, 79, 221, 192, 198, 47, 31, 35, 218, 57, 7, 155, 131];
const S : [u8;32] = [16, 75, 111, 66, 108, 136, 172, 253, 112, 144, 219, 98, 182, 77, 18, 226, 85, 135, 92, 46, 121, 158, 41, 70, 119, 135, 114, 10, 92, 200, 59, 154];
const V : u64 = 0;

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

    let test_sig = Signature {
        r: R.into(),
        s: S.into(),
        v: V
    };

    println!("Signature: {:?}", test_sig);
    println!("---------------------------------");
    
    let raw_tx_bytes = tx.rlp_signed(&test_sig);
    let raw_tx_hex = format!("0x{}", hex::encode(&raw_tx_bytes));

    //println!("Raw transaction hash: {:?}", raw_tx_bytes.hash());
    println!("Raw transaction (for broadcasting):\n{}", raw_tx_hex);
    println!("---------------------------------");

}