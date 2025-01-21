//!
//! CONJUGATE CODING LIBRARY
//!
//! This mini library allows to implement conjugate-coding based
//! one-time programs. It contains all the needed
//! tooling to recover a bitstring from a conjugate-coding
//! measurement.
//!
//! This library should be paired with asymmetric key crypto
//! and run on a TEE to make sure the protocol developed
//! is cryptographically secure.
//!
//! Example protocol run:
//!
//! SENDING PARTY CALLS:
//! conjugate_coding_init: sets
//!      -- The secret string lenght;
//!      -- The amount of supplementary security bits to use.
//! conjugate_coding_setup: sets
//!      -- The orderings (which qubits encode which bits);
//!      -- The bit mask (which bits are security string);
//!      -- The values that the measurement should have at
//!         the bitmask location, depending on the choice of measurement basis.
//!
//! SENDING PARTY SENDS THE QUBITS ECODING THE CLASSICAL BITS
//!      This part is outside of this codebase and is performed using
//!      Conjugate coding on a standard QKD setup.
//!
//! RECEIVING PARTY MEASURES THE QUBITS
//!      Again, outside of this codebease and performed QKD-style.
//!
//! RECEIVING PARTY CALLS:
//! conjugate_coding_measure: sets
//!      -- The measurement outcomes;
//!      -- The choices of measurement basis for each couple of qubits.
//! conjugate_coding_purge_noise: purges the measurement bit string
//!      from the noise introduced by conjugate coding.
//! conjugate_coding_verify: verified that at specific locations specify by
//!      the bitmask, measurement outcomes are as expected.
//!      This ensures the information stored in orderings cannot be extracted
//!      by replaying the protocol.
//! conjugate_coding_compute_secret: purges the bitstring from the security bits,
//!      thus returing the final secret string.
//!

extern crate alloc;
use alloc::vec::Vec;
use alloc::boxed::Box;

use esp_alloc as _;
use esp_println::{print, println};

use core::assert_eq;

/// Ensure memory protection over cryptographically sensitive data.
use secrecy::{ExposeSecret, SecretBox};
/// Ensure that cryptographically sensitive data is zeroed into oblivion after use.
use zeroize::{Zeroize, ZeroizeOnDrop};

//#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ConjugateCodingContext {
    ///
    /// The whole protocol status is stored in a struct.
    /// Different actors provide different portions of this struct.
    ///
    /// secret_size, security_size, orderings, bitmsecurity, security1
    /// are set by the party preparing the qubits.
    ///
    /// meas_outcomes, meas_choices
    /// are set by the party measuring the qubits.
    ///
    /// total_size, purged_outcomes, secret
    /// are computed at different stages of the protocol.
    /// Size in bytes of the final secret.  Normally 32.
    secret_size: usize,
    /// Size in bytes of the security bits. Normally 32.
    security_size: usize,
    /// secret_size + security_size. Normally 64.
    total_size: usize,
    /// For each couple of qubits in conjugate coding, which qubit encodes which bit. For each bit, 0 means '1st qbit encodes 1st bit'. Length of the array equals total_size.
    orderings: SecretBox<Vec<u8>>,
    /// The bit mask array, which says which bits of purged_outcomes are used for security. Length equals total_size. Must contain precisely security_size 1s and secret_size 0s.
    bitmask: SecretBox<Vec<u8>>,
    /// The measurement outcomes array. Length equals to 2*total_size.
    meas_outcomes: SecretBox<Vec<u8>>,
    /// The choices of bases for each couple of measurements. Length equals total_size.
    meas_choices: SecretBox<Vec<u8>>,
    /// The measurement_outcomes array purged from measurement noise. Length equals measurement_outcomes/2.
    purged_outcomes: SecretBox<Vec<u8>>,
    /// The array used for checking security in the 0 measurement case. Length equals security_size.
    security0: SecretBox<Vec<u8>>,
    /// The array used for checking security in the 1 measurement case. Length equals security_size.
    security1: SecretBox<Vec<u8>>,
    /// The purged_outcomes array purged from the security bits. It encodes the final secret bitstring. Legnth equals secret_size.
    secret: SecretBox<Vec<u8>>,
}

///
/// @brief   Prints the current protocol context to screen.
///
/// @param ctx:       Pointer to the context struct;
/// @param format:    Bitstring format: b binary (default), x hex, d decimal.
///
///
fn conjugate_coding_print_context(ctx: &ConjugateCodingContext) {
    println!("===============");
    println!("PROTOCOL CONTEXT");
    println!("++++++++++++++++");
    println!("Provided by preparing party");
    println!("----------------");
    println!("secret_size:    {}", ctx.secret_size);
    println!("security_size:    {}", ctx.security_size);
    println!("----------------");
    println!("orderings");
    println!(
        "size:    {}/{}",
        &ctx.orderings.expose_secret().len(),
        &ctx.orderings.expose_secret().capacity()
    );
    println!("value:    {:?}", &ctx.orderings.expose_secret());
    println!("----------------");
    println!("bitmask");
    println!(
        "size:    {}/{}",
        &ctx.bitmask.expose_secret().len(),
        &ctx.bitmask.expose_secret().capacity()
    );
    println!("value:    {:?}", &ctx.bitmask.expose_secret());
    println!("----------------");
    println!("security parameters 0");
    println!(
        "size:    {}/{}",
        &ctx.security0.expose_secret().len(),
        &ctx.security0.expose_secret().capacity()
    );
    println!("value:    {:?}", &ctx.security0.expose_secret());
    println!("----------------");
    println!("security parameters 1");
    println!(
        "size:    {}/{}",
        &ctx.security1.expose_secret().len(),
        &ctx.security1.expose_secret().capacity()
    );
    println!("value:    {:?}", &ctx.security1.expose_secret());
    println!("++++++++++++++++");
    println!("++++++++++++++++");
    println!("Provided by preparing party");
    println!("----------------");
    println!("measurement outcomes");
    println!(
        "size:    {}/{}",
        &ctx.meas_outcomes.expose_secret().len(),
        &ctx.meas_outcomes.expose_secret().capacity()
    );
    println!("value:    {:?}", &ctx.meas_outcomes.expose_secret());
    println!("----------------");
    println!("choices of bases");
    println!(
        "size:    {}/{}",
        &ctx.meas_choices.expose_secret().len(),
        &ctx.meas_choices.expose_secret().capacity()
    );
    println!("value:    {:?}", &ctx.meas_choices.expose_secret());
    println!("++++++++++++++++");
    println!("++++++++++++++++");
    println!("Computed");
    println!("----------------");
    println!("total_size:    {}", ctx.total_size);
    println!("----------------");
    println!("Purged outcomes");
    println!(
        "size:    {}/{}",
        &ctx.purged_outcomes.expose_secret().len(),
        &ctx.purged_outcomes.expose_secret().capacity()
    );
    println!("value:    {:?}", &ctx.purged_outcomes.expose_secret());
    println!("----------------");
    println!("Secret");
    println!(
        "size:    {}/{}",
        &ctx.secret.expose_secret().len(),
        &ctx.secret.expose_secret().capacity()
    );
    println!("value:    {:?}", &ctx.secret.expose_secret());
    println!("++++++++++++++++");
}

///
/// @brief   Sets the size in bytes for secret_size and security_size in the protocol context.
///          Proceed by reserving all the needed memory in the protocol context.
///
///          Should be called by the party preparing the qubits.
///
/// @param ctx:            Pointer to the context struct;
/// @param secret_size:    How many bytes we want to the secret bitstring to be. Suggested default is 32;
/// @param security_size:  How many bytes we want to use as security bits. Suggested default is 32.
///
///
fn conjugate_coding_init(secret_size: usize, security_size: usize) -> ConjugateCodingContext {
    let ctx: ConjugateCodingContext = ConjugateCodingContext {
        secret_size,
        security_size,
        total_size: secret_size + security_size,
        orderings: SecretBox::new(Box::new(Vec::with_capacity(secret_size + security_size))),
        bitmask: SecretBox::new(Box::new(Vec::with_capacity(secret_size + security_size))),
        security0: SecretBox::new(Box::new(Vec::with_capacity(security_size))),
        security1: SecretBox::new(Box::new(Vec::with_capacity(security_size))),
        meas_outcomes: SecretBox::new(Box::new(Vec::with_capacity(
            2 * (secret_size + security_size),
        ))),
        meas_choices: SecretBox::new(Box::new(Vec::with_capacity(secret_size + security_size))),
        purged_outcomes: SecretBox::new(Box::new(Vec::with_capacity(secret_size + security_size))),
        secret: SecretBox::new(Box::new(Vec::with_capacity(secret_size))),
    };

    ctx
}

// Helper function. Checks if the n-th bit of a byte is 1.
fn is_nth_bit_set(byte: u8, bit: usize) -> bool {
    let mask: [u8; 8] = [128, 64, 32, 16, 8, 4, 2, 1];

    byte & mask[bit] != 0
}

fn vector_is_balanced(vec: Vec<u8>, secret_size: usize, security_size: usize) {
    let (mut zeroes, mut ones): (usize, usize) = (0, 0);
    for byte in vec.iter() {
        for j in 0..8 {
            if is_nth_bit_set(*byte, j) {
                ones += 1;
            } else {
                zeroes += 1;
            }
        }
    }
    assert_eq!(
        zeroes,
        8 * secret_size,
        "Vector is not balanced. There are {} zeroes instead of {}.",
        zeroes,
        8 * secret_size
    );
    assert_eq!(
        ones,
        8 * security_size,
        "Vector is not balanced. There are {} zeroes instead of {}.",
        ones,
        8 * security_size
    );
}
