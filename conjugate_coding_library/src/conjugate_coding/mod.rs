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
//! All structs used implement Zeroize and ZeroizeOnDrop,
//! ensuring memory is overwritten after use.
//! 
//! Library is no_std friendly.
//! 
//! Example protocol run:
//!
//! SENDING PARTY CALLS:
//! ConjugateCodingPrepare.new(): sets
//!      -- The secret string lenght;
//!      -- The amount of supplementary security bits to use.
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
//! conjugateCodingMeasure.new(&preparation: ConjugateCodingPrepare): sets
//!      -- The measurement outcomes;
//!      -- The choices of measurement basis for each couple of qubits.
//! conjugateCodingResult.new(
//!    &preparation: ConjugateCodingPrepare,
//!    &measurement: ConjugateCodingMeasure
//!   ). This function performs several tasks:
//!      -- Purges the measurement bit string from the noise introduced by conjugate coding;
//!      -- Verifies that at specific locations specified by the bitmask, 
//!         measurement outcomes are as expected. This ensures the information
//!         stored in orderings cannot be extracted by replaying the protocol;
//!      -- If the verification passes, purges the bitstring from the 
//!         security bits, thus returing the final secret string.
//!


pub extern crate alloc;
pub use alloc::boxed::Box;
pub use alloc::vec::Vec;
pub use alloc::vec;

#[cfg(not(feature = "std"))]
pub use esp_println::println;
#[cfg(not(feature = "std"))]
pub use core::writeln;

#[cfg(feature = "defmt")]
use defmt::{Format, Formatter, write};
#[cfg(feature = "std")]
use core::fmt;

use serde::Deserialize;

/// Ensure memory protection over cryptographically sensitive data.
/// Track every time a secret is accessed. Moreover, ensure that 
/// cryptographically sensitive data is zeroed into oblivion after use.
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

#[derive(Deserialize)]
pub struct ConjugateCodingPrepare {
    ///
    /// All information from the qubit preparing party
    /// is encapsulated in this structure.
    /// 
    /// Size in bytes of the final secret.  Normally 32;
    secret_size:   usize,
    /// Size in bytes of the security bits. Normally 32;
    security_size: usize,
    /// secret_size + security_size. Normally 64;
    pub total_size:    usize,
    /// For each couple of qubits in conjugate coding, which qubit encodes which bit. For each bit, 0 means '1st qbit encodes 1st bit'. Length of the array equals total_size;
    orderings:     SecretBox<Vec<u8>>,
    /// The bit mask array, which says which bits of purged_outcomes are used for security. Length equals total_size. Must contain precisely security_size 1s and secret_size 0s;
    bitmask:       SecretBox<Vec<u8>>,
    /// The array used for checking security in the 0 measurement case. Length equals security_size;
    security0:     SecretBox<Vec<u8>>,
    /// The array used for checking security in the 1 measurement case. Length equals security_size.
    security1:     SecretBox<Vec<u8>>,
}

impl Zeroize for ConjugateCodingPrepare {
    fn zeroize(&mut self) {
        self.secret_size = 0;
        self.security_size = 0;
        self.total_size = 0;
        self.orderings.zeroize();
        self.bitmask.zeroize();
        self.security0.zeroize();
        self.security1.zeroize();
    }
}

impl ZeroizeOnDrop for ConjugateCodingPrepare {}

#[derive(Deserialize)]
pub enum ConjugateCodingPrepareError {
    // orderings vector has the wrong length
    OrderingsWL,
    // bitmask vector has the wrong length
    BitmaskWL,
    // security0 vector has the wrong length
    Security0WL,
    // security1 vector has the wrong length
    Security1WL,
    // bitmask vector is not balanced
    BitmaskNotBalanced,
}

#[cfg(feature = "std")]
impl fmt::Debug for ConjugateCodingPrepareError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConjugateCodingPrepareError::OrderingsWL => {
                write!(fmt, "\"Orderings bitstring has the wrong length\"")
            }
            ConjugateCodingPrepareError::BitmaskWL => {
                write!(fmt, "\"Bitmask bitstring has the wrong length\"")
            }
            ConjugateCodingPrepareError::Security0WL => {
                write!(fmt, "\"Security0 bitstring has the wrong length\"")
            }
            ConjugateCodingPrepareError::Security1WL => {
                write!(fmt, "\"Security1 bitstring bitstring has the wrong length\"")
            }
            ConjugateCodingPrepareError::BitmaskNotBalanced => {
                write!(fmt, "\"Bitmask bitstring is not balanced\"")
            }
        }
    }
}

#[cfg(feature = "defmt")]
impl Format for ConjugateCodingPrepareError {
    fn format(&self, fmt: Formatter) {
        match self {
            ConjugateCodingPrepareError::OrderingsWL => {
                write!(fmt, "\"Orderings bitstring has the wrong length\"")
            }
            ConjugateCodingPrepareError::BitmaskWL => {
                write!(fmt, "\"Bitmask bitstring has the wrong length\"")
            }
            ConjugateCodingPrepareError::Security0WL => {
                write!(fmt, "\"Security0 bitstring has the wrong length\"")
            }
            ConjugateCodingPrepareError::Security1WL => {
                write!(fmt, "\"Security1 bitstring bitstring has the wrong length\"")
            }
            ConjugateCodingPrepareError::BitmaskNotBalanced => {
                write!(fmt, "\"Bitmask bitstring is not balanced\"")
            }
        }
    }
}


impl ConjugateCodingPrepare {

    #[cfg(feature = "debug")]
    ///
    /// @brief   Prints struct information on screen.
    ///
    pub fn diagnostics(&self) {
        println!("===============");
        println!("PREPARATION CONTEXT");
        println!("++++++++++++++++");
        println!("----------------");
        println!("secret_size:    {}", self.secret_size);
        println!("security_size:    {}", self.security_size);
        println!("total_size:    {}", self.total_size);
        println!("----------------");
        println!("orderings");
        println!(
            "size:    {}/{}",
            self.orderings.expose_secret().len(),
            self.orderings.expose_secret().capacity()
        );
        println!("value:    {:?}", self.orderings.expose_secret());
        println!("----------------");
        println!("bitmask");
        println!(
            "size:    {}/{}",
            self.bitmask.expose_secret().len(),
            self.bitmask.expose_secret().capacity()
        );
        println!("value:    {:?}", self.bitmask.expose_secret());
        println!("----------------");
        println!("security parameters 0");
        println!(
            "size:    {}/{}",
            self.security0.expose_secret().len(),
            self.security0.expose_secret().capacity()
        );
        println!("value:    {:?}", self.security0.expose_secret());
        println!("----------------");
        println!("security parameters 1");
        println!(
            "size:    {}/{}",
            self.security1.expose_secret().len(),
            self.security1.expose_secret().capacity()
        );
        println!("value:    {:?}", self.security1.expose_secret());
        println!("===============");
    }

    /// @brief   Sets the struct fields. Automatically checks that all
    ///          the vectors provided are of the right length, and that
    ///          bitmask contains precisely security_size 1s and secret_size 0s.
    ///
    ///          Should be called by the party preparing the qubits.
    ///
    /// @param secret_size:    How many bytes we want to the secret bitstring to be. Suggested default is 32;
    /// @param security_size:  How many bytes we want to use as security bits. Suggested default is 32.
    /// @param orderings:      The orderings vector, of length secret_size + security_size;
    /// @param bitmask:        The bitmask vector, of length secret_size + security_size;
    /// @param security0:      The security values vector for 1st bit measurements, of length security_size;
    /// @param security1:      The security values vector for 2nd bit measurements, of length security_size.
    ///
    pub fn new(
        secret_size: usize,
        security_size: usize,
        orderings: SecretBox<Vec<u8>>,
        bitmask: SecretBox<Vec<u8>>,
        security0: SecretBox<Vec<u8>>,
        security1: SecretBox<Vec<u8>>,
    ) -> Result<ConjugateCodingPrepare, Vec<ConjugateCodingPrepareError>> {
        let total_size = secret_size + security_size;
        let mut error_vec: Vec<ConjugateCodingPrepareError> = Vec::new();

        if orderings.expose_secret().len() != total_size {
            error_vec.push(ConjugateCodingPrepareError::OrderingsWL);
        }
        if bitmask.expose_secret().len() != total_size {
            error_vec.push(ConjugateCodingPrepareError::BitmaskWL);
        }
        if security0.expose_secret().len() != security_size {
            error_vec.push(ConjugateCodingPrepareError::Security0WL);
        }
        if security1.expose_secret().len() != security_size {
            error_vec.push(ConjugateCodingPrepareError::Security1WL);
        }
        if !Self::vector_is_balanced(&bitmask, secret_size, security_size) {
            error_vec.push(ConjugateCodingPrepareError::BitmaskNotBalanced);
        }
        if error_vec.len() > 0 {
            return Err(error_vec);
        }

        Ok(ConjugateCodingPrepare {
            secret_size,
            security_size,
            total_size,
            orderings,
            bitmask,
            security0,
            security1,
        })
        
    }

    /// @brief   Creates a struct filled with zero values.
    ///
    pub fn new_from_zero() -> ConjugateCodingPrepare {
        return ConjugateCodingPrepare {
            secret_size: 0,
            security_size: 0,
            total_size: 0,
            orderings: SecretBox::new(Box::new(vec![0;0])),
            bitmask: SecretBox::new(Box::new(vec![0;0])),
            security0: SecretBox::new(Box::new(vec![0;0])),
            security1: SecretBox::new(Box::new(vec![0;0])),
        }
    }

    /// @brief   Works as new, but accepts plaintext values and boxes them automatically.
    ///
    ///          Should be called by the party preparing the qubits.
    ///
    /// @param secret_size:    How many bytes we want to the secret bitstring to be. Suggested default is 32;
    /// @param security_size:  How many bytes we want to use as security bits. Suggested default is 32.
    /// @param orderings:      The orderings vector, of length secret_size + security_size;
    /// @param bitmask:        The bitmask vector, of length secret_size + security_size;
    /// @param security0:      The security values vector for 1st bit measurements, of length security_size;
    /// @param security1:      The security values vector for 2nd bit measurements, of length security_size.
    ///
    pub fn new_plaintext(
        secret_size: usize,
        security_size: usize,
        orderings: Vec<u8>,
        bitmask: Vec<u8>,
        security0: Vec<u8>,
        security1: Vec<u8>,
    ) -> Result<ConjugateCodingPrepare, Vec<ConjugateCodingPrepareError>> {

        let boxed_orderings = SecretBox::new(Box::new(orderings));
        let boxed_bitmask = SecretBox::new(Box::new(bitmask));
        let boxed_security0 = SecretBox::new(Box::new(security0));
        let boxed_security1 = SecretBox::new(Box::new(security1));

        return Self::new(
            secret_size,
            security_size,
            boxed_orderings,
            boxed_bitmask,
            boxed_security0,
            boxed_security1
        );
    }
    
    fn vector_is_balanced(vec: &SecretBox<Vec<u8>>, secret_size: usize, security_size: usize) -> bool {
        let (mut zeroes, mut ones): (usize, usize) = (0, 0);
        for byte in vec.expose_secret().iter() {
            for bit in 0..8 {
                if is_nth_bit_set(*byte, bit) { ones += 1; } else { zeroes += 1 }
            }
        }
        if zeroes == 8 * secret_size && ones == 8 * security_size { true } else { false }
    }

}

#[derive(Deserialize, Debug)]
pub struct ConjugateCodingMeasure {
    ///
    /// All information from the qubit measuring party
    /// is encapsulated in this structure.
    /// 
    /// The measurement outcomes vector. Length equals to 2*total_size.
    outcomes: SecretBox<Vec<u8>>,
    /// The choices of bases for each couple of measurements. Length equals total_size.
    choices: SecretBox<Vec<u8>>,
}

impl Zeroize for ConjugateCodingMeasure {
    fn zeroize(&mut self) {
        self.outcomes.zeroize();
        self.choices.zeroize();
    }
}

impl ZeroizeOnDrop for ConjugateCodingMeasure {}

pub enum ConjugateCodingMeasureError {
    // outcomes vector has the wrong length
    OutcomesWL,
    // choiches vector has the wrong length
    ChoicesWL,
}

#[cfg(feature = "std")]
impl fmt::Debug for ConjugateCodingMeasureError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConjugateCodingMeasureError::OutcomesWL => {
                write!(fmt, "\"Measurement outcomes bitstring has the wrong length\"")
            }
            ConjugateCodingMeasureError::ChoicesWL => {
                write!(fmt, "\"Choice of measurement basis bitstring has the wrong length\"")
            }
        }
    }
}

#[cfg(feature = "defmt")]
impl Format for ConjugateCodingMeasureError {
    fn format(&self, fmt: Formatter) {
        match self {
            ConjugateCodingMeasureError::OutcomesWL => {
                write!(fmt, "\"Measurement outcomes bitstring has the wrong length\"")
            }
            ConjugateCodingMeasureError::ChoicesWL => {
                write!(fmt, "\"Choice of measurement basis bitstring has the wrong length\"")
            }
        }
    }
}

impl ConjugateCodingMeasure {
    
    #[cfg(feature = "debug")]
    ///
    /// @brief   Prints struct information on screen.
    ///
    pub fn diagnostics(&self) {
        println!("===============");
        println!("MEASUREMENT CONTEXT");
        println!("++++++++++++++++");
        println!("----------------");
        println!("measurement outcomes");
        println!(
            "size:    {}/{}",
            self.outcomes.expose_secret().len(),
            self.outcomes.expose_secret().capacity()
        );
        println!("value:    {:?}", self.outcomes.expose_secret());
        println!("----------------");
        println!("choices of bases");
        println!(
            "size:    {}/{}",
            self.choices.expose_secret().len(),
            self.choices.expose_secret().capacity()
        );
        println!("value:    {:?}", self.choices.expose_secret());
        println!("===============");
    }

    /// @brief   Sets the struct fields. Automatically verifies that
    ///          all vectors provided are of the right length.
    ///
    ///          Should be called by the party preparing the qubits.
    /// 
    /// @param preparation:   A reference to the preparation context;
    /// @outcomes:            The orderings vector, of length 2*(secret_size + security_size);
    /// @choices:             The vector containing choices of measurement bases, of length (secret_size + security_size).
    ///
    pub fn new(
        preparation: &ConjugateCodingPrepare,
        outcomes: SecretBox<Vec<u8>>,
        choices: SecretBox<Vec<u8>>,
    ) -> Result<ConjugateCodingMeasure, Vec<ConjugateCodingMeasureError>> {

        let mut error_vec: Vec<ConjugateCodingMeasureError> = Vec::new();

        if outcomes.expose_secret().len() != 2*preparation.total_size {
            error_vec.push(ConjugateCodingMeasureError::OutcomesWL);
        }
        if choices.expose_secret().len() != preparation.total_size {
            error_vec.push(ConjugateCodingMeasureError::ChoicesWL);
        }
        if error_vec.len() > 0 {
            return Err(error_vec);
        }

        Ok(ConjugateCodingMeasure {
            outcomes,
            choices,
        })
    }

    /// @brief   Creates a struct filled with zero values.
    ///
    pub fn new_from_zero() -> ConjugateCodingMeasure {
        return ConjugateCodingMeasure {
            outcomes: SecretBox::new(Box::new(vec![0;0])),
            choices: SecretBox::new(Box::new(vec![0;0])),
        }
    }

    /// @brief   Works as new, but accepts plaintext values and boxes them automatically.
    ///
    ///          Should be called by the party preparing the qubits.
    /// 
    /// @param preparation:   A reference to the preparation context;
    /// @outcomes:            The orderings vector, of length 2*(secret_size + security_size);
    /// @choices:             The vector containing choices of measurement bases, of length (secret_size + security_size).
    ///
    pub fn new_plaintext(
        preparation: &ConjugateCodingPrepare,
        outcomes: Vec<u8>,
        choices: Vec<u8>,
    ) -> Result<ConjugateCodingMeasure, Vec<ConjugateCodingMeasureError>> {

        let boxed_outcomes = SecretBox::new(Box::new(outcomes));
        let boxed_choices = SecretBox::new(Box::new(choices));

        return Self::new(
            preparation,
            boxed_outcomes,
            boxed_choices,
        );
    }
    

}

pub struct ConjugateCodingResult {
    /// The measurement_outcomes array purged from measurement noise. Length equals measurement_outcomes/2.
    purged: SecretBox<Vec<u8>>,
    /// The purged_outcomes array purged from the security bits. It encodes the final secret bitstring. Legnth equals secret_size.
    secret: SecretBox<Vec<u8>>,
}

impl Zeroize for ConjugateCodingResult {
    fn zeroize(&mut self) {
        self.purged.zeroize();
        self.secret.zeroize();
    }
}

impl ZeroizeOnDrop for ConjugateCodingResult {}

pub enum ConjugateCodingResultError {
    VerificationFailed
}

#[cfg(feature = "std")]
impl fmt::Debug for ConjugateCodingResultError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConjugateCodingResultError::VerificationFailed => {
                write!(fmt, "Verification failed. Some security bits were tripped.")
            }
        }
    }
}

#[cfg(feature = "defmt")]
impl Format for ConjugateCodingResultError {
    fn format(&self, fmt: Formatter) {
        match self {
            ConjugateCodingResultError::VerificationFailed => {
                write!(fmt, "Verification failed. Some security bits were tripped.")
            }
        }
    }
}

impl ConjugateCodingResult {

    #[cfg(feature = "debug")]
    ///
    /// @brief   Prints struct information on screen.
    ///
    pub fn diagnostics(&self) {
        println!("===============");
        println!("COMPUTED CONTEXT");
        println!("++++++++++++++++");
        println!("----------------");
        println!("Purged outcomes");
        println!(
            "size:    {}/{}",
            self.purged.expose_secret().len(),
            self.purged.expose_secret().capacity()
        );
        println!("value:    {:?}", self.purged.expose_secret());
        println!("----------------");
        println!("Secret");
        println!(
            "size:    {}/{}",
            self.secret.expose_secret().len(),
            self.secret.expose_secret().capacity()
        );
        println!("value:    {:?}", self.secret.expose_secret());
        println!("===============");
    }

    /// @brief   Sets the struct fields. Automatically verifies
    ///          that the measurement context passes the security
    ///          verification as dictated by the prepare context.
    /// 
    ///          Should be called by the party preparing the qubits.
    /// 
    /// @param preparation:   A reference to the preparation context;
    /// @param measurements:  A reference to the measurement context.
    ///
    pub fn new(
        preparation: &ConjugateCodingPrepare,
        measurement: &ConjugateCodingMeasure,
    ) -> Result<ConjugateCodingResult, ConjugateCodingResultError>{

        let purged: SecretBox<Vec<u8>> = Self::purge_noise(&preparation, &measurement);

        match Self::verify(&preparation,&measurement, &purged,0) {
            Ok(()) => {
                let secret: SecretBox<Vec<u8>> = Self::compute_secret(&preparation, &purged);
                Ok(ConjugateCodingResult{
                    purged,
                    secret,
                })
            },
            Err(error) => {
                return Err(error);
            }
        }
    }

    ///
    /// @brief   Breaks outcomes in the measurement context into chunks of 2 bits;
    ///          For the i-th chunk, it uses choices[i] (which bit we wanted to measure)
    ///          and orderings[i] (which qubit encoded which bit) in the context to determine
    ///          which bit in the chunk to keep.
    ///          Then stores the result in the protocol context.
    ///
    /// @param preparation:   A reference to the preparation context;
    /// @param measurements:  A reference to the measurement context.
    ///
    /// @return purged:       The measurement.outcomes vector, purged from noise.
    ///
    fn purge_noise (
        preparation: &ConjugateCodingPrepare,
        measurement: &ConjugateCodingMeasure,
    ) -> SecretBox<Vec<u8>> {
        let mut purged:Vec<u8> = Vec::new();
        for byte in 0..preparation.total_size {
            let mut mask: u8 = 0;
            let xor = measurement.choices.expose_secret()[byte] ^ preparation.orderings.expose_secret()[byte];
            for bit in 0..8 {
                // Case 0: we keep the 1st bit and discard the 2nd.
                if is_nth_bit_set(xor,bit) == false {
                    // j = 0 -> meas_outcomes[2i],   0th bit
                    // j = 1 -> meas_outcomes[2i],   2nd bit
                    // j = 2 -> meas_outcomes[2i],   4th bit
                    // j = 3 -> meas_outcomes[2i],   6th bit
                    // j = 4 -> meas_outcomes[2i+1], 0th bit
                    // j = 5 -> meas_outcomes[2i+1], 2nd bit
                    // j = 6 -> meas_outcomes[2i+1], 4th bit
                    // j = 7 -> meas_outcomes[2i+1], 6th bit
                    if is_nth_bit_set(measurement.outcomes.expose_secret()[2*byte + (bit/4)],(2*bit)%8) {
                        mask += 1 << (7-bit);
                    }
                // Case 1: we keep the 2nd bit and discard the 1st.
                } else {
                    // j = 0 -> meas_outcomes[2i],   1st bit
                    // j = 1 -> meas_outcomes[2i],   3rd bit
                    // j = 2 -> meas_outcomes[2i],   5th bit
                    // j = 3 -> meas_outcomes[2i],   7th bit
                    // j = 4 -> meas_outcomes[2i+1], 1st bit
                    // j = 5 -> meas_outcomes[2i+1], 3rd bit
                    // j = 6 -> meas_outcomes[2i+1], 5th bit
                    // j = 7 -> meas_outcomes[2i+1], 7th bit
                    if is_nth_bit_set(measurement.outcomes.expose_secret()[2*byte + (bit/4)],((2*bit)%8)+1) {
                        mask += 1 << (7-bit);
                    }
                }
            }
            purged.push(mask);
        }
        return SecretBox::new(Box::new(purged));    
    }

    ///
    /// @brief   The actual security check. It verifies that the quantum measurement
    ///          has actually happened and that the receiving party isn't feeding us
    ///          bullshit bits. Does so by looking at the protocol context,
    ///          and using the information at bitmask to single out bits in purged_outcomes.
    ///          For each bit, depending on the choice of measurement basis, it checks
    ///          if it equals the corresponding valye in eisecurity or security1.
    ///          
    ///          Since the receiving party doesn't know the bitstring, bruteforcing the
    ///          security proof would require to call this function, in the worst case:
    ///          \f[
    ///              \sum_{i=1}^security_size biomialCoefficient(total_size, i)
    ///          \f]
    ///
    /// @param preparation:   A reference to the preparation context;
    /// @param measurements:  A reference to the measurement context;
    /// @param purged:        A reference to the purged mesurements vector.
    /// @param error:         The error tolerance in the verification procedure, 
    ///                       defining the Hamming distance radius within which a
    ///                       bitstring is considered acceptable.
    ///
    fn verify (
        preparation: &ConjugateCodingPrepare,
        measurement: &ConjugateCodingMeasure,
        purged: &SecretBox<Vec<u8>>,
        error: usize
    )  -> Result<(), ConjugateCodingResultError> {
    
        // We keep the count of how many 1s in the bitmask we encountered so far.
        let mut bitmask_bit_counter: usize = 0;
        let mut trip_bits = 0;
        for byte in 0..preparation.total_size {
            for bit in 0..8 {
                // We found a 1 in the bitmask. So this is a security bit and we
                // need to check against our security0 and security1 tables.
                if is_nth_bit_set(preparation.bitmask.expose_secret()[byte], bit) {
                    // If we measured the 1st bit, we need to use security0.
                    if !is_nth_bit_set(measurement.choices.expose_secret()[byte], bit) {
                        // The actual check. When it fails we increment the error counter.
                        if is_nth_bit_set(purged.expose_secret()[byte],bit)
                            != is_nth_bit_set(preparation.security0.expose_secret()[bitmask_bit_counter/8],bitmask_bit_counter%8) {
                                trip_bits += 1;
                            }
                    // If we measured the 2nd bit, we need to use security1.
                    } else {
                        // The actual check. When it fails we increment the error counter.
                        if is_nth_bit_set(purged.expose_secret()[byte],bit)
                            != is_nth_bit_set(preparation.security1.expose_secret()[bitmask_bit_counter/8],bitmask_bit_counter%8) {
                                trip_bits += 1;
                            }                        
                    }
                    bitmask_bit_counter += 1;
                }
            }
        }
        if trip_bits > error { return Err(ConjugateCodingResultError::VerificationFailed) }
        Ok(())
    }

    ///
    // @brief   Looks at bitmask and purged in the computed context,
    ///          purges purged of the security bits and stores the result
    ///          into secret.
    ///
    /// @param preparation:  Pointer to the preparation context
    /// @param purged:       Pointer to the measurement vector, purged from noise.
    ///
    fn compute_secret(
        preparation: &ConjugateCodingPrepare,
        purged: &SecretBox<Vec<u8>>
    ) -> SecretBox<Vec<u8>>{

        let mut secret:Vec<u8> = Vec::new();
        let mut mask:u8;

        for byte in 0.. preparation.total_size {
            mask = 0;
            for bit in 0..8 {
                // We found a 0 in the bitmask. This value we keep.
                if !is_nth_bit_set(preparation.bitmask.expose_secret()[byte],bit) 
                    && is_nth_bit_set(purged.expose_secret()[byte],bit)
                    { mask += 1 << (7 - bit) }                
            }
            secret.push(mask);
        }
        return SecretBox::new(Box::new(secret));    
    }
}

// Helper function. Checks if the n-th bit of a byte is 1.
fn is_nth_bit_set(byte: u8, bit: usize) -> bool {
    let mask: [u8; 8] = [128, 64, 32, 16, 8, 4, 2, 1];
    byte & mask[bit] != 0
}

// TODO. We should use a fuzzer to create random vectors, and feed them to the protocol.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_nth_bit_set_test() {
        let zero: u8 = 0b00000000;
        let fst: u8  = 0b10000000;
        let snd: u8  = 0b01000000;
        let trd: u8  = 0b00100000;
        let fth: u8  = 0b00010000;
        let fft: u8  = 0b00001000;
        let sth: u8  = 0b00000100;
        let svt: u8  = 0b00000010;
        let eth: u8  = 0b00000001;
        assert!(is_nth_bit_set(fst, 0));
        assert!(is_nth_bit_set(snd, 1));
        assert!(is_nth_bit_set(trd, 2));
        assert!(is_nth_bit_set(fth, 3));
        assert!(is_nth_bit_set(fft, 4));
        assert!(is_nth_bit_set(sth, 5));
        assert!(is_nth_bit_set(svt, 6));
        assert!(is_nth_bit_set(eth, 7));

        for bit in 0..8 {
        assert!(!is_nth_bit_set(zero, bit));
        if bit != 0 {
            assert!(!is_nth_bit_set(fst, bit))
        }
        if bit != 1 {
            assert!(!is_nth_bit_set(snd, bit))
        }
        if bit != 2 {
            assert!(!is_nth_bit_set(trd, bit))
        }
        if bit != 3 {
            assert!(!is_nth_bit_set(fth, bit))
        }
        if bit != 4 {
            assert!(!is_nth_bit_set(fft, bit))
        }
        if bit != 5 {
            assert!(!is_nth_bit_set(sth, bit))
        }
        if bit != 6 {
            assert!(!is_nth_bit_set(svt, bit))
        }
        if bit != 7 {
            assert!(!is_nth_bit_set(eth, bit))
        }
        }
    }
}