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
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::writeln;
use esp_alloc as _;
use esp_println::println;

use core::assert_eq;

/// Ensure memory protection over cryptographically sensitive data.
use secrecy::{ExposeSecret, SecretBox};
/// Ensure that cryptographically sensitive data is zeroed into oblivion after use.
//use zeroize_derive::{Zeroize, ZeroizeOnDrop};

//#[derive(Zeroize, ZeroizeOnDrop)]
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
    total_size:    usize,
    /// For each couple of qubits in conjugate coding, which qubit encodes which bit. For each bit, 0 means '1st qbit encodes 1st bit'. Length of the array equals total_size;
    orderings:     SecretBox<Vec<u8>>,
    /// The bit mask array, which says which bits of purged_outcomes are used for security. Length equals total_size. Must contain precisely security_size 1s and secret_size 0s;
    bitmask:       SecretBox<Vec<u8>>,
    /// The array used for checking security in the 0 measurement case. Length equals security_size;
    security0:     SecretBox<Vec<u8>>,
    /// The array used for checking security in the 1 measurement case. Length equals security_size.
    security1:     SecretBox<Vec<u8>>,
}

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
    BitmaskUnbalanced,
}

impl ConjugateCodingPrepare {

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

    /// @brief   Sets the struct fields.
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
            error_vec.push(ConjugateCodingPrepareError::BitmaskUnbalanced);
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
    
    fn vector_is_balanced(vec: &SecretBox<Vec<u8>>, secret_size: usize, security_size: usize) -> bool {
        let (mut zeroes, mut ones): (usize, usize) = (0, 0);
        for byte in vec.expose_secret().iter() {
            for bit in 0..8 {
                if is_nth_bit_set(*byte, bit) {
                    ones += 1;
                } else {
                    zeroes += 1;
                }
            }
        }
    
        if zeroes == 8 * secret_size && ones == 8 * security_size {
            true
        } else {
            false
        }
    }
}

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

pub enum ConjugateCodingMeasureError {
    // outcomes vector has the wrong length
    OutcomesWL,
    // choiches vector has the wrong length
    ChoicesWL,
}

impl ConjugateCodingMeasure {
    
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

   /// @brief   Sets the struct fields.
    ///
    ///          Should be called by the party preparing the qubits.
    /// @outcomes: The orderings vector, of length 2*(secret_size + security_size);
    /// @choices:  The vector containing choices of measurement bases, of length (secret_size + security_size).
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

}

pub struct ConjugateCodingResult {
    /// The measurement_outcomes array purged from measurement noise. Length equals measurement_outcomes/2.
    purged: SecretBox<Vec<u8>>,
    /// The purged_outcomes array purged from the security bits. It encodes the final secret bitstring. Legnth equals secret_size.
    secret: SecretBox<Vec<u8>>,
}

pub enum ConjugateCodingResultError {
    // outcomes vector has the wrong length
    Security0Fail,
    // choiches vector has the wrong length
    Security1Fail,
}

impl ConjugateCodingResult {

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

    /// @brief   Sets the struct fields.
    ///
    ///          Should be called by the party preparing the qubits.
    /// @param preparation:   A reference to the preparation context;
    /// @param measurements:  A reference to the measurement context.
    ///
    pub fn new(
        preparation: &ConjugateCodingPrepare,
        measurement: &ConjugateCodingMeasure,
    ) -> Result<ConjugateCodingResult, Vec<ConjugateCodingResultError>>{ //-> Result<ConjugateCodingResult, Vec<ConjugateCodingResultError>> {

        let purged: SecretBox<Vec<u8>> = Self::purge_noise(&preparation, &measurement);
        match Self::verify(&preparation,&measurement, &purged) {
            Ok(()) => {
                let secret = Self::compute_secret(&preparation, &purged);
                Ok(ConjugateCodingResult{
                    purged,
                    secret,
                })
            },
            Err(error_vec) => {
                return Err(error_vec);
            }
        }

      //  let mut error_vec: Vec<ConjugateCodingMeasureError> = Vec::new();

        // if outcomes.expose_secret().len() != 2*preparation.total_size {
        //     error_vec.push(ConjugateCodingMeasureError::OutcomesWL);
        // }
        // if choices.expose_secret().len() != preparation.total_size {
        //     error_vec.push(ConjugateCodingMeasureError::ChoicesWL);
        // }
        // if error_vec.len() > 0 {
        //     return Err(error_vec);
        // }

        // Ok(ConjugateCodingResult {
        //     outcomes,
        //     choices,
        // })
    }

    ///
    /// @brief   Breaks meas_outcomes in the protocol context into chunks of 2 bits;
    ///          For the i-th chunk, it uses meas_choices[i] (which bit we wanted to measure)
    ///          and orderings[i] (which qubit encoded which bit) in the context to determine
    ///          which bit in the chunk to keep.
    ///          Then stores the result in the protocol context.
    ///
    ///          Should be called by the party receiving the qubits, after measurement is performed.
    ///
    /// @param preparation:   A reference to the preparation context;
    /// @param measurements:  A reference to the measurement context.
    ///
    /// @return purged:       The measurement.outcomes vector, purged from noise.
    fn purge_noise (
        preparation: &ConjugateCodingPrepare,
        measurement: &ConjugateCodingMeasure,
    ) -> SecretBox<Vec<u8>> {
        let mut purged:Vec<u8> = Vec::new();
        for byte in 0..preparation.total_size {
            let xor = measurement.choices.expose_secret()[byte] ^ preparation.orderings.expose_secret()[byte];
            for bit in 0..8 {
                let mut mask: u8 = 0;
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
                        mask = 1 << (7-bit);
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
                        mask = 1 << (7-bit);
                    }
                }
                purged.push(mask);
            }
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
    ///          security proof requires to call this function, in the worst case:
    ///          \f[
    ///              \sum_{i=1}^security_size biomialCoefficient(total_size, i)
    ///          \f]
    ///
    ///          Should be called by the party receiving the qubits, after measurement is performed.
    ///
    /// @param preparation:   A reference to the preparation context;
    /// @param measurements:  A reference to the measurement context;
    /// @param purged:        A reference to the purged mesurements vector.
    ///
    fn verify (
        preparation: &ConjugateCodingPrepare,
        measurement: &ConjugateCodingMeasure,
        purged: &SecretBox<Vec<u8>>
    )  -> Result<(), Vec<ConjugateCodingResultError>> {
        let mut error_vec: Vec<ConjugateCodingResultError> = Vec::new();
    
        // We keep the count of how many 1s in the bitmask we encountered so far.
        let mut counter: usize = 0;

        for byte in 0..preparation.total_size {
            for bit in 0..8 {
                // We found a 1 in the bitmask!
                if is_nth_bit_set(preparation.bitmask.expose_secret()[byte], bit) {
                    // If we measured the 1st bit, we need to use security0.
                    if !is_nth_bit_set(measurement.choices.expose_secret()[byte], bit) {
                        if is_nth_bit_set(purged.expose_secret()[byte],bit)
                            != is_nth_bit_set(preparation.security0.expose_secret()[counter/8],counter%8) {
                                error_vec.push(ConjugateCodingResultError::Security0Fail);
                            }
                    // If we measured the 2nd bit, we need to use security1.
                    } else {
                        if is_nth_bit_set(purged.expose_secret()[byte],bit)
                            != is_nth_bit_set(preparation.security1.expose_secret()[counter/8],counter%8) {
                                error_vec.push(ConjugateCodingResultError::Security1Fail);
                            }                        
                    }
                    counter += 1;
                }
            }
            if counter == 8*preparation.security_size {
                break;
            }
        }

        if error_vec.len() > 0 {
            return Err(error_vec);
        }

        Ok(())
    }

    ///
    // @brief   Looks at bitmask and purged_outcomes in the protocol context,
    ///          purges purged_outcomes of the security bits and stores the result
    ///          into secret.
    ///
    ///          Should be called by the party receiving the qubits, after measurement is performed.
    ///
    /// @param preparation:  Pointer to the preparation context
    /// @param purged:       Pointer to the measurement vector, purged from noise.
    ///
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
