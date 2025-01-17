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

/// Ensure memory protection over cryptographically sensitive data.
use secrecy::SecretBox;
/// Ensure that cryptographically sensitive data is zeroed into oblivion after use.
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
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

fn main() {
    println!("Hello, world!");
}
