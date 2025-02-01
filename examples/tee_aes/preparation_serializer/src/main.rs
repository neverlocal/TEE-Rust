// AES PASSWORD TO COMMUNICATE WITH THE TEE
const SHARED_SECRET: &[u8] = "SUp4SeCp@sSw0rd".as_bytes();

// Logging facilities
use env_logger;
use log::{trace, debug, warn, error};
// Easy read from console
#[macro_use]
extern crate text_io;
// Serialization stuff
use hex;
use serde::{Serialize, Serializer};
// Rewrite memory locations with 0s after drop, useful for security reasons
use zeroize::{Zeroize, ZeroizeOnDrop};

// Cryptography
use sha2::{Sha256, Digest};
use aes::Aes256;
use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit};

// Our library!
use conjugate_coding::{self, conjugate_coding::ConjugateCodingPrepare};


//////////////////
// CRYPTOGRAPHY //
//////////////////
// Compute the sha256 of an input
fn hash256(buffer: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    trace!("[ hash256 ] hasher initialized.");
    hasher.update(buffer);
    trace!("[ hash256 ] hasher updated.");
    return hasher.finalize().into();
}

// Encrypt/Decrypt an input using AES
#[allow(dead_code)]
enum Mode {
    Encryption256,
    Decryption256
}
fn aes256(buffer: Vec<u8>, mode: Mode) -> Vec<u8> {
    let keybuf = hash256(SHARED_SECRET).into();
    trace!("[ aes256 ] Secret key hashed.");
    trace!("[ aes256 ] Key hash: {:x?}", keybuf);
    let cipher = Aes256::new(&keybuf);
    trace!("[ aes256 ] Cypher initialized.");
    let mut blocks: Vec<[u8; 16]> = Vec::new();
    trace!("[ aes256 ] Chopping input into chunks of 16 bytes.");
    let mut i = 0;
    while i < buffer.len() {
        trace!("[ aes256 ] Operating on chunk: {:?}", i);
        let remaining = buffer.len() - i;
        let current_chunk_size = core::cmp::min(16, remaining); // Handle last chunk
        let mut chunk = [0u8; 16];
        let data_slice = &buffer[i..i + current_chunk_size];
        chunk[..data_slice.len()].copy_from_slice(data_slice);
        trace!("[ aes256 ] Chunk: {:x?}", chunk);
        blocks.push(chunk);
        i += 16;
    }
    trace!("[ aes256 ] Chunk vector: {:x?}", blocks);
    for j in 0..blocks.len() {
        match mode {
            Mode::Encryption256 => {
                trace!("[ aes256 ] Encrypting chunk: {:?}", j);
                trace!("[ aes256 ] Decrypted chunk: {:x?}", blocks[j]);
                let mut block = blocks[j].into();
                cipher.encrypt_block(&mut block);
                blocks[j] = block.into();
                trace!("[ aes256 ] Encrypted chunk: {:x?}", block);
                trace!("[ aes256 ] Encrypted chunk: {:x?}", blocks[j]);
            }
            Mode::Decryption256 => {
                trace!("[ aes256 ] Decrypting chunk: {:?}", j);
                trace!("[ aes256 ] Encrypted chunk: {:x?}", blocks[j]);
                cipher.decrypt_block(&mut blocks[j].into());
                trace!("[ aes256 ] Decrypted chunk: {:x?}", blocks[j]);
            }
        }
    }
    let mut flattened = Vec::new();
    trace!("[ aes256 ] Flattening chunk vector.");
    for chunk in blocks {
        flattened.extend_from_slice(&chunk);
    }
    trace!("[ aes256 ] Flattened vector: {:x?}", flattened);
    return flattened;
}

// Data structure holding all the needed params in one place.
#[derive(Zeroize, ZeroizeOnDrop, Serialize)]
struct ConjugateCodingPreparePlaintext {
    security_size: usize,
    orderings: Vec<u8>,
    security0: Vec<u8>,
    security1: Vec<u8>,
}

// We serialize vectors as hex strings to save memory in the TEE.
fn serialize_vec_to_hex_string<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(bytes))
}

// We implement the custom serialization function
// We convert the Vec<u8> into arrays of bytes on the flight,
// then serialize them as hex strings.
impl ConjugateCodingPreparePlaintext {
    fn serialize(&self) -> Result<String, serde_json::Error> {
        // Use #[serde(serialize_with = "...")] to apply the custom serializer
        #[derive(Serialize)]
        struct HexPlainData<'a> {
            security_size: usize,
            #[serde(serialize_with = "serialize_vec_to_hex_string")]
            orderings: &'a [u8],
            #[serde(serialize_with = "serialize_vec_to_hex_string")]
            security0: &'a [u8],
            #[serde(serialize_with = "serialize_vec_to_hex_string")]
            security1: &'a [u8],
        }
        // Create a temporary struct with the same data
        let hex_data = HexPlainData {
            security_size: self.security_size,
            orderings: &self.orderings,
            security0: &self.security0,
            security1: &self.security1,
        };
        serde_json::to_string(&hex_data)
    }
}

// A state machine implementing the core protocol
#[derive(Debug)]
enum StateMachine {
    FirstDialog,    // Greetings etc.
    SecurityInput,  // User inputs security_size
    OrderingsInput, // User inputs orderings bitstring
    Security0Input, // User inputs security0 bitstring
    Security1Input, // User inputs security1 bitstring
    Output,         // Checks are performed, JSON outputted
}

fn main() {
    use StateMachine::{FirstDialog, SecurityInput, OrderingsInput, Security0Input, Security1Input, Output};
    std::env::set_var("RUST_LOG", "warn"); // Set the logging level
    env_logger::builder()
        .format_target(false)
        .format_timestamp(None)
        .init(); // Avoid displaying timestamps in logs
    debug!("Environment logger set and initialized.");

    let mut plain_data = ConjugateCodingPreparePlaintext {
        security_size: 0,
        orderings: vec![0; 0],
        security0: vec![0; 0],
        security1: vec![0; 0],
    };
    debug!("plain_data initialized.");

    let mut state_machine: StateMachine = FirstDialog;
    debug!("Protocol state machine initialized.");
    loop {
        match state_machine {
            FirstDialog => {
                println!("==================================================");
                debug!("[ {:?} ] Displaying first greeting.", FirstDialog);
                println!("This is TEE-Rust - Preparation serializer utility.");
                println!("--------------------------------------------------");
                println!(
                    "The purpose of this program is to acquire all the\n\
                          relevant preparation data, and print them in a way\n\
                          that the TEE-Rust Esp32c6 example can acquire."
                );
                warn!(  
                    "The current utility uses AES to exchange preparation\n    \
                       results. This is insecure for a lot of reasons. At the\n    \
                       bare minimum, we would like to have a MAC on top of it\n    \
                       or use a AEAD directly. Even better, we would like to \n    \
                       switch to a quantum-resistant version of TLS. We have \n    \
                       not yet done this because the standards are still in  \n    \
                       the process of being discussed/approved. All in all,  \n    \
                       this application is useful for educational purposes   \n    \
                       only. Use at your own risk!"
                );
                state_machine = SecurityInput;
                debug!("[ {:?} ] Protocol transitioned to state 'SecurityInput'.", FirstDialog);
            }
            SecurityInput => {
                println!("--------------------------------------------------");
                debug!("[ {:?} ] Displaying request for security bytes.", SecurityInput);
                println!("Enter the number of security bytes:");
                let parsed: String = read!("{}\n");
                debug!("[ {:?} ] String captured. string: {}", SecurityInput, parsed);
                match parsed.parse::<usize>() {
                    Err(e) => {
                        error!("Input is not a positive number! Please try again.");
                        debug!("[ {:?} ] String parsed incorrectly. Error: {}", SecurityInput, e);
                        plain_data.security_size = 0;
                        debug!(
                            "[ {:?} ] security_size wiped. security_size: {}",
                            SecurityInput,
                            plain_data.security_size
                        );
                        debug!("[ {:?} ] Protocol transitioned to state 'SecurityInput'.", SecurityInput);
                    }
                    Ok(output) => {
                        debug!(
                            "[ SecurityInput ] String parsed correctly. output: {}",
                            output
                        );
                        plain_data.security_size = output;
                        debug!(
                            "[ {:?} ] security_size assigned value: {}",
                            SecurityInput,
                            plain_data.security_size
                        );
                        state_machine = OrderingsInput;
                        debug!("[ {:?} ] Protocol transitioned to state 'OrderingsInput'.", SecurityInput)
                    }
                }
            }
            OrderingsInput => {
                println!("--------------------------------------------------");
                debug!("[ {:?} ] Displaying request for orderings bitstring.", OrderingsInput);
                println!(
                    "Please enter the ORDERINGS bitstring. You will need\n\
                          to provide {} bytes, in binary form. You will be\n\
                          asked for one byte at a time. Do not use any special\n\
                          characters. Only strings consisting of 0s and 1s, of\n\
                          maximum length 8, are allowed.",
                    plain_data.security_size
                );
                println!("EXAMPLE:");
                println!("Please provide byte 0:");
                println!("01001110");
                println!("-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~");
                let mut i = 0;
                while i < plain_data.security_size {
                    println!(
                        "ORDERINGS bytes already provided (in hex notation): {:x?}",
                        plain_data.orderings
                    );
                    println!("Please provide byte {}:", i);
                    let parsed: String = read!("{}\n");
                    debug!("[ {:?} ] String captured. string: {}", OrderingsInput, parsed);
                    if parsed.len() > 8 {
                        error!("Maximum number of characters per string is 8, you entered {}. Try again!", parsed.len());
                    } else {
                        match u8::from_str_radix(&parsed, 2) {
                            Err(e) => {
                                error!("Not a valid bitstring! Try again!");
                                debug!("[ {:?} ] Error: {}", OrderingsInput, e);
                            }
                            Ok(result) => {
                                plain_data.orderings.push(result);
                                debug!("[ {:?} ] New valued pushed.: {}", OrderingsInput, result);
                                i += 1;
                            }
                        }
                    }
                }
                debug!(
                    "[ {:?} ] Exited while loop. orderings: {:x?}",
                    OrderingsInput,
                    plain_data.orderings
                );
                state_machine = Security0Input;
                debug!("[ {:?} ] Protocol transitioned to state 'Security0Input'.", OrderingsInput);
            }
            Security0Input => {
                debug!("[ {:?} ] Checking size of security_size", Security0Input);
                if plain_data.security_size == 0 {
                    state_machine = Output;
                        debug!("[ {:?} ] security_size is 0. Protocol transitioned to state 'Output'.", Security0Input);
                } else {
                    debug!("[ {:?} ] security_size is bigger than 0.", Security0Input);
                    println!("--------------------------------------------------");
                    debug!("[ {:?} ] Displaying request for security0 bitstring.", Security0Input);
                    println!(
                        "Please enter the SECURITY0 bitstring. This is the\n\
                        bitstring of security parameters when the measured\n\
                        bit is 0. You will need to provide {} bytes, in\n\
                        binary form. You will be asked for one byte at a\n\
                        time. Do not use any special characters. Only\n\
                        strings consisting of 0s and 1s, of maximum length\n\
                        8, are allowed.",
                        plain_data.security_size
                    );
                    println!("EXAMPLE:");
                    println!("Please provide byte 0:");
                    println!("01001110");
                    println!("-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~");
                    let mut i = 0;
                    while i < plain_data.security_size {
                        println!(
                            "SECURITY0 bytes already provided (in hex notation): {:x?}",
                            plain_data.security0
                        );
                        println!("Please provide byte {}:", i);
                        let parsed: String = read!("{}\n");
                        debug!("[ {:?} ] String captured. string: {}", Security0Input, parsed);
                        if parsed.len() > 8 {
                            error!("Maximum number of characters per string is 8, you entered {}. Try again!", parsed.len());
                        } else {
                            match u8::from_str_radix(&parsed, 2) {
                                Err(e) => {
                                    error!("Not a valid bitstring! Try again!");
                                    debug!("[ {:?} ] Error: {}", Security0Input, e);
                                }
                                Ok(result) => {
                                    plain_data.security0.push(result);
                                    debug!("[ {:?} ] New valued pushed.: {}", Security0Input, result);
                                    i += 1;
                                }
                            }
                        }
                    }
                    debug!(
                        "[ {:?} ] Exited while loop. security0: {:x?}",
                        Security0Input,
                        plain_data.security0
                    );
                    state_machine = Security1Input;
                    debug!("[ {:?} ] Protocol transitioned to state 'Security1Input'.", Security0Input);
                }
            }
            Security1Input => {
                println!("--------------------------------------------------");
                debug!("[ {:?} ] Displaying request for security1 bitstring.", Security1Input);
                println!(
                    "Please enter the SECURITY1 bitstring. This is the\n\
                      bitstring of security parameters when the measured\n\
                      bit is 1. You will need to provide {} bytes, in\n\
                      binary form. You will be asked for one byte at a\n\
                      time. Do not use any special characters. Only\n\
                      strings consisting of 0s and 1s, of maximum length\n\
                      8, are allowed.",
                    plain_data.security_size
                );
                println!("EXAMPLE:");
                println!("Please provide byte 0:");
                println!("01001110");
                println!("-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~");
                let mut i = 0;
                while i < plain_data.security_size {
                    println!(
                        "SECURITY1 bytes already provided (in hex notation): {:x?}",
                        plain_data.security1
                    );
                    println!("Please provide byte {}:", i);
                    let parsed: String = read!("{}\n");
                    debug!("[ {:?} ] String captured. string: {}", Security1Input, parsed);
                    if parsed.len() > 8 {
                        error!("Maximum number of characters per string is 8, you entered {}. Try again!", parsed.len());
                    } else {
                        match u8::from_str_radix(&parsed, 2) {
                            Err(e) => {
                                error!("Not a valid bitstring! Try again!");
                                debug!("[ {:?} ] Error: {}", Security1Input, e);
                            }
                            Ok(result) => {
                                plain_data.security1.push(result);
                                debug!("[ {:?} ] New valued pushed.: {}", Security1Input, result);
                                i += 1;
                            }
                        }
                    }
                }
                debug!(
                    "[ {:?} ] Exited while loop. security1: {:x?}",
                    Security1Input,
                    plain_data.security1
                );
                state_machine = Output;
                debug!("[ {:?} ] Protocol transitioned to state 'Output'.", Security1Input);
            }
            Output => {
                println!("--------------------------------------------------");
                debug!("[ {:?} ] Displaying greeting message.", Output);
                println!(
                    "Thank you for having provided all the needed\n\
                        information. I will need a second to validate it."
                );
                match ConjugateCodingPrepare::new_plaintext(
                    0,
                    plain_data.security_size,
                    plain_data.orderings.clone(),
                    vec![255;plain_data.security_size], //Bitmask is all 1 in this particular application!
                    plain_data.security0.clone(),
                    plain_data.security1.clone()
                ) {
                    Ok(_) => { // ConjugateCodingPrepare is not serializable, so we discard it
                        match plain_data.serialize() {
                            Ok(result) => {
                                debug!("[ {:?} ] Serialized data: {:?}", Output, result);
                                debug!("[ {:?} ] Serialized data (hex): {:x?}", Output, result.as_bytes());
                                println!("Data is valid and has been serialized correctly. It will now be encrypted.");
                                let encrypted_result = aes256(result.into_bytes(), Mode::Encryption256);
                                println!("Your data has been correctly encrypted. Here it is!");
                                println!();
                                println!("{}", &hex::encode(&encrypted_result));
                                println!();
                                debug!("[ {:?} ] Encrypted data (hex): {:x?}", Output, &hex::encode(&encrypted_result).as_bytes());
                                println!("Use it as you see fit. Have a nice day!");
                            }
                            Err(e) => error!("Something went wrong: Error: {:?}. Please try again!", e)
                        }
                    }
                    Err(e) => error!("Your data could not pass validation for the following reason(s): {:?}. Please start again.",e)
                };
                break;
            }
        }
    }
    debug!("We are out of the main loop.");
    plain_data.zeroize();
    debug!("We zeroized protocol variables just in case. Exiting.");
}