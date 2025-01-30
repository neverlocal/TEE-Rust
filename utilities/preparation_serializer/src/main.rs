// Logging facilities
use env_logger;
use log::{debug, error, warn};
// Easy read from console
#[macro_use]
extern crate text_io;
// Serializatin stuff
use hex;
use serde::{Serialize, Serializer};
// Rewrite memory locations with 0s after drop
// Useful for security reasons
use zeroize::{Zeroize, ZeroizeOnDrop};
// Our library!
use conjugate_coding::{self, conjugate_coding::ConjugateCodingPrepare};

// Data structure holding all the needed params in one place.
#[derive(Zeroize, ZeroizeOnDrop, Serialize)]
struct PlainData {
    secret_size: usize,
    security_size: usize,
    orderings: Vec<u8>,
    bitmask: Vec<u8>,
    security0: Vec<u8>,
    security1: Vec<u8>,
}

// We serialize vectors as hex strings to save memory in the TEE.
fn serialize_vec_as_hex_string<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(bytes))
}

// We implement the custom serialization function
// We convert the Vec<u8> into arrays of bytes on the flight,
// then serialize them as hex strings.
impl PlainData {
    fn serialize(&self) -> Result<String, serde_json::Error> {
        // Use #[serde(serialize_with = "...")] to apply the custom serializer
        #[derive(Serialize)]
        struct HexPlainData<'a> {
            secret_size: usize,
            security_size: usize,
            #[serde(serialize_with = "serialize_vec_as_hex_string")]
            orderings: &'a [u8],
            #[serde(serialize_with = "serialize_vec_as_hex_string")]
            bitmask: &'a [u8],
            #[serde(serialize_with = "serialize_vec_as_hex_string")]
            security0: &'a [u8],
            #[serde(serialize_with = "serialize_vec_as_hex_string")]
            security1: &'a [u8],
        }
        // Create a temporary struct with the same data
        let hex_data = HexPlainData {
            secret_size: self.secret_size,
            security_size: self.security_size,
            orderings: &self.orderings,
            bitmask: &self.bitmask,
            security0: &self.security0,
            security1: &self.security1,
        };
        serde_json::to_string(&hex_data)
    }
}

// A state machine implementing the core protocol
enum StateMachine {
    FirstDialog,    // Greetings etc.
    SecretInput,    // User inputs secret_size
    SecurityInput,  // User inputs security_size
    OrderingsInput, // User inputs orderings bitstring
    BitmaskInput,   // User inputs bitmask bitstring
    Security0Input, // User inputs security0 bitstring
    Security1Input, // User inputs security1 bitstring
    Output,         // Checks are performed, JSON outputted
}

fn main() {
    std::env::set_var("RUST_LOG", "info"); // Set the logging level
    env_logger::builder()
        .format_target(false)
        .format_timestamp(None)
        .init(); // Avoid displaying timestamps in logs
    debug!("Environment logger set and initialized.");

    let mut plain_data = PlainData {
        secret_size: 0,
        security_size: 0,
        orderings: vec![0; 0],
        bitmask: vec![0; 0],
        security0: vec![0; 0],
        security1: vec![0; 0],
    };
    debug!("plain_data initialized.");

    let mut total_size = 0;
    debug!("total_size initialized.");

    let mut state_machine: StateMachine = StateMachine::FirstDialog;
    debug!("Protocol state machine initialized.");
    loop {
        match state_machine {
            StateMachine::FirstDialog => {
                println!("==================================================");
                debug!("[ FirstDialog ] Displaying first greeting.");
                println!("This is TEE-Rust - Preparation serializer utility.");
                println!("--------------------------------------------------");
                println!(
                    "The purpose of this program is to acquire all the\n\
                          relevant preparation data, and print them in a way\n\
                          that the TEE-Rust Esp32c6 example can acquire."
                );
                warn!(
                    "The current utility serializes preparation\n    \
                       results in plaintext. This is cryptographically\n    \
                       insecure, and useful only for educational\n    \
                       purposes. Use at your own risk!"
                );
                state_machine = StateMachine::SecretInput;
                debug!("[ FirstDialog ] Protocol transitioned to 'SecretInput'.");
            }
            StateMachine::SecretInput => {
                println!("--------------------------------------------------");
                debug!("[ SecretInput ] Displaying request for secret bytes.");
                println!("Enter the number of secret bytes:");
                let parsed: String = read!("{}\n");
                debug!("[ SecretInput ] String captured. string: {}", parsed);
                match parsed.parse::<usize>() {
                    Ok(output) => {
                        debug!(
                            "[ SecretInput ] String parsed correctly. output: {}",
                            output
                        );
                        plain_data.secret_size = output;
                        debug!(
                            "[ SecretInput ] secret_size assigned value: {}",
                            plain_data.secret_size
                        );
                        state_machine = StateMachine::SecurityInput;
                        debug!("[ SecretInput ] Protocol transitioned to 'SecurityInput'.")
                    }
                    Err(e) => {
                        error!("Input is not a positive number! Please try again.");
                        debug!("[ SecretInput ] String parsed incorrectly. Error: {}", e);
                        plain_data.secret_size = 0;
                        debug!(
                            "[ SecretInput ] secret_size wiped. secret_size: {}",
                            plain_data.secret_size
                        );
                        debug!("[ SecretInput ] Protocol transitioned to 'SecretInput'.");
                    }
                }
            }
            StateMachine::SecurityInput => {
                println!("--------------------------------------------------");
                debug!("[ SecurityInput ] Displaying request for security bytes.");
                println!("Enter the number of security bytes:");
                let parsed: String = read!("{}\n");
                debug!("[ SecurityInput ] String captured. string: {}", parsed);
                match parsed.parse::<usize>() {
                    Ok(output) => {
                        debug!(
                            "[ SecurityInput ] String parsed correctly. output: {}",
                            output
                        );
                        plain_data.security_size = output;
                        debug!(
                            "[ SecurityInput ] security_size assigned value: {}",
                            plain_data.security_size
                        );
                        state_machine = StateMachine::OrderingsInput;
                        debug!("[ SecurityInput ] Protocol transitioned to 'OrderingsInput'.")
                    }
                    Err(e) => {
                        error!("Input is not a positive number! Please try again.");
                        debug!("[ SecurityInput ] String parsed incorrectly. Error: {}", e);
                        plain_data.security_size = 0;
                        debug!(
                            "[ SecurityInput ] security_size wiped. security_size: {}",
                            plain_data.security_size
                        );
                        debug!("[ SecurityInput ] Protocol transitioned to 'SecurityInput'.");
                    }
                }
            }
            StateMachine::OrderingsInput => {
                println!("--------------------------------------------------");
                debug!("[ OrderingsInput ] Displaying request for orderings bitstring.");
                total_size = plain_data.secret_size + plain_data.security_size;
                debug!("[ OrderingsInput ] total_size set to {}", total_size);
                println!(
                    "Please enter the ORDERINGS bitstring. You will need\n\
                          to provide {} bytes, in binary form. You will be\n\
                          asked for one byte at a time. Do not use any special\n\
                          characters. Only strings consisting of 0s and 1s, of\n\
                          maximum length 8, are allowed.",
                    total_size
                );
                println!("EXAMPLE:");
                println!("Please provide byte 0:");
                println!("01001110");
                println!("-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~");
                let mut i = 0;
                while i < total_size {
                    println!(
                        "ORDERINGS bytes already provided (in hex notation): {:x?}",
                        plain_data.orderings
                    );
                    println!("Please provide byte {}:", i);
                    let parsed: String = read!("{}\n");
                    debug!("[ OrderingsInput ] String captured. string: {}", parsed);
                    if parsed.len() > 8 {
                        error!("Maximum number of characters per string is 8, you entered {}. Try again!", parsed.len());
                    } else {
                        match u8::from_str_radix(&parsed, 2) {
                            Err(e) => {
                                error!("Not a valid bitstring! Try again!");
                                debug!("[ OrderingsInput ] Error: {}", e);
                            }
                            Ok(result) => {
                                plain_data.orderings.push(result);
                                debug!("[ OrderingsInput ] New valued pushed.: {}", result);
                                i += 1;
                            }
                        }
                    }
                }
                debug!(
                    "[ OrderingsInput ] Exited while loop. orderings: {:x?}",
                    plain_data.orderings
                );
                state_machine = StateMachine::BitmaskInput;
                debug!("[ OrderingsInput ] Protocol transitioned to 'BitmaskInput'.");
            }
            StateMachine::BitmaskInput => {
                println!("--------------------------------------------------");
                debug!("[ BitmaskInput ] Displaying request for bitmask bitstring.");
                println!(
                    "Please enter the BITMASK bitstring. You will need\n\
                          to provide {} bytes, in binary form. You will be\n\
                          asked for one byte at a time. Do not use any special\n\
                          characters. Only strings consisting of 0s and 1s, of\n\
                          maximum length 8, are allowed.",
                    total_size
                );
                println!("EXAMPLE:");
                println!("Please provide byte 0:");
                println!("01001110");
                println!("-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~");
                let mut i = 0;
                while i < total_size {
                    println!(
                        "BITMASK bytes already provided (in hex notation): {:x?}",
                        plain_data.bitmask
                    );
                    println!("Please provide byte {}:", i);
                    let parsed: String = read!("{}\n");
                    debug!("[ BitmaskInput ] String captured. string: {}", parsed);
                    if parsed.len() > 8 {
                        error!("Maximum number of characters per string is 8, you entered {}. Try again!", parsed.len());
                    } else {
                        match u8::from_str_radix(&parsed, 2) {
                            Err(e) => {
                                error!("Not a valid bitstring! Try again!");
                                debug!("[ BitmaskInput ] Error: {}", e);
                            }
                            Ok(result) => {
                                plain_data.bitmask.push(result);
                                debug!("[ BitmaskInput ] New valued pushed.: {}", result);
                                i += 1;
                            }
                        }
                    }
                }
                debug!(
                    "[ BitmaskInput ] Exited while loop. bitmask: {:x?}",
                    plain_data.bitmask
                );
                state_machine = StateMachine::Security0Input;
                debug!("[ BitmaskInput ] Protocol transitioned to 'Security0Input'.");
            }
            StateMachine::Security0Input => {
                println!("--------------------------------------------------");
                debug!("[ Security0Input ] Displaying request for security0 bitstring.");
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
                    debug!("[ Security0Input ] String captured. string: {}", parsed);
                    if parsed.len() > 8 {
                        error!("Maximum number of characters per string is 8, you entered {}. Try again!", parsed.len());
                    } else {
                        match u8::from_str_radix(&parsed, 2) {
                            Err(e) => {
                                error!("Not a valid bitstring! Try again!");
                                debug!("[ Security0Input ] Error: {}", e);
                            }
                            Ok(result) => {
                                plain_data.security0.push(result);
                                debug!("[ Security0Input ] New valued pushed.: {}", result);
                                i += 1;
                            }
                        }
                    }
                }
                debug!(
                    "[ Security0Input ] Exited while loop. security0: {:x?}",
                    plain_data.security0
                );
                state_machine = StateMachine::Security1Input;
                debug!("[ Security0Input ] Protocol transitioned to 'Security1Input'.");
            }
            StateMachine::Security1Input => {
                println!("--------------------------------------------------");
                debug!("[ Security1Input ] Displaying request for security1 bitstring.");
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
                    debug!("[ Security1Input ] String captured. string: {}", parsed);
                    if parsed.len() > 8 {
                        error!("Maximum number of characters per string is 8, you entered {}. Try again!", parsed.len());
                    } else {
                        match u8::from_str_radix(&parsed, 2) {
                            Err(e) => {
                                error!("Not a valid bitstring! Try again!");
                                debug!("[ Security1Input ] Error: {}", e);
                            }
                            Ok(result) => {
                                plain_data.security1.push(result);
                                debug!("[ Security1Input ] New valued pushed.: {}", result);
                                i += 1;
                            }
                        }
                    }
                }
                debug!(
                    "[ Security1Input ] Exited while loop. security1: {:x?}",
                    plain_data.security1
                );
                state_machine = StateMachine::Output;
                debug!("[ Security1Input ] Protocol transitioned to 'Output'.");
            }
            StateMachine::Output => {
                println!("--------------------------------------------------");
                debug!("[ Output ] Displaying greeting message.");
                println!(
                    "
                    Thank you for having provided all the needed\n\
                        information. I will need a second to validate it."
                );
                match ConjugateCodingPrepare::new_plaintext(
                    plain_data.secret_size,
                    plain_data.security_size,
                    plain_data.orderings.clone(),
                    plain_data.bitmask.clone(),
                    plain_data.security0.clone(),
                    plain_data.security1.clone()
                ) {
                    Ok(_) => { // ConjugateCodingPrepare is not serializable, so we discard it
                        match plain_data.serialize() {
                            Ok(result) => {
                                debug!("Data has been serialized correctly and will now be displayed.");
                                println!("Your data has been correctly serialized. Here it is!");
                                println!();
                                println!("{}",result);
                                println!();
                                println!("Use it as you see fit. Have a nice day!");
                            }
                            Err(e) => error!("Something went wrong: Error: {:?}. Please try again!", e)
                        }
                    }
                    Err(e) => error!("Your data could not pass validation for the following reason: {:?}. Please start again.",e)
                };
                break;
            }
        }
    }
    debug!("We are out of the main loop.");
    plain_data.zeroize();
    total_size.zeroize();
    debug!("We zeroized protocol variables just in case. Exiting.");
}