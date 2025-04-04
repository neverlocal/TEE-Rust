//////////////////////
// CONJUGATE CODING //
//////////////////////
use alloc::string::String;
use hex::{self};
use serde::de::Error;
use defmt::Format;

extern crate alloc; // no_std requires a custom allocator
use alloc::vec::Vec; // Needed for buffer manipulation

use zeroize::{Zeroize, ZeroizeOnDrop}; // Rewrite memory locations with 0s after drop, useful for security reasons

use core::result::Result; // Manipulate errors

use serde::{Deserialize, Deserializer}; // We do like our JSON very much

// Custom deserializer for Vec<u8> from hex string
fn deserialize_vec_from_hex_string<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    hex::decode(&s).map_err(Error::custom)
}

// Structure to store submitted preparation information
#[derive(Zeroize, ZeroizeOnDrop, Deserialize, Format)]
pub struct ConjugateCodingPreparePlaintext {
    pub security_size: usize,
    pub orderings: Vec<u8>,
    pub security0: Vec<u8>,
    pub security1: Vec<u8>,
}

impl ConjugateCodingPreparePlaintext {
    pub fn deserialize(json_vec: &[u8]) -> Result<Self, serde_json::Error> {
        #[derive(Deserialize)]
        struct HexPlainData {
            security_size: usize,
            #[serde(deserialize_with = "deserialize_vec_from_hex_string")]
            orderings: Vec<u8>,
            #[serde(deserialize_with = "deserialize_vec_from_hex_string")]
            security0: Vec<u8>,
            #[serde(deserialize_with = "deserialize_vec_from_hex_string")]
            security1: Vec<u8>,
        }

        let hex_data: HexPlainData = serde_json::from_slice(json_vec)?;

        Ok(ConjugateCodingPreparePlaintext {
            security_size: hex_data.security_size,
            orderings: hex_data.orderings,
            security0: hex_data.security0,
            security1: hex_data.security1,
        })
    }
}
