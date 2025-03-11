// Logging facilities
use env_logger;
use log::{debug, error};
// Easy read from console
#[macro_use]
extern crate text_io;
// Serializatin stuff
use hex;
use serde::{Serialize, Serializer};

// Data structure holding all the needed params in one place.
#[derive(Serialize)]
struct ConjugateCodingMeasurePlaintext {
    outcomes: Vec<u8>
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
impl ConjugateCodingMeasurePlaintext {
    fn serialize(&self) -> Result<String, serde_json::Error> {
        // Use #[serde(serialize_with = "...")] to apply the custom serializer
        #[derive(Serialize)]
        struct HexPlainData<'a> {
            #[serde(serialize_with = "serialize_vec_to_hex_string")]
            outcomes: &'a [u8]
        }
        // Create a temporary struct with the same data
        let hex_data = HexPlainData {
            outcomes: &self.outcomes
        };
        serde_json::to_string(&hex_data)
    }
}

// A state machine implementing the core protocol
#[derive(Debug)]
enum StateMachine {
    FirstDialog,   // Greetings etc.
    SizeInput,     // User inputs total_size
    OutcomesInput, // User inputs outcomes bitstring
    Output,        // Checks are performed, JSON outputted
}

fn main() {
    use StateMachine::{FirstDialog, SizeInput, OutcomesInput, Output};
    std::env::set_var("RUST_LOG", "info"); // Set the logging level
    env_logger::builder()
        .format_target(false)
        .format_timestamp(None)
        .init(); // Avoid displaying timestamps in logs
    debug!("Environment logger set and initialized.");

    let mut plain_data = ConjugateCodingMeasurePlaintext {
        outcomes: vec![0; 0]
    };
    debug!("plain_data initialized.");

    let mut total_size = 0;
    debug!("total_size initialized.");

    let mut state_machine: StateMachine = FirstDialog;
    debug!("Protocol state machine initialized.");
    loop {
        match state_machine {
            FirstDialog => {
                println!("==================================================");
                debug!("[ {:?} ] Displaying first greeting.", FirstDialog);
                println!("This is TEE-Rust - Measurement serializer utility.");
                println!("--------------------------------------------------");
                println!(
                    "The purpose of this program is to acquire all the\n\
                          relevant measurement data, and print them in a way\n\
                          that the TEE-Rust Esp32c6 example can acquire."
                );
                state_machine = SizeInput;
                debug!("[ {:?} ] Protocol transitioned to state 'SizeInput'.", FirstDialog);
            }
            SizeInput => {
                println!("--------------------------------------------------");
                debug!("[ {:?} ] Displaying request for total number of bytes.", SizeInput);
                println!("Enter the total number of classical bytes to recover:");
                let parsed: String = read!("{}\n");
                debug!("[ {:?} ] String captured. string: {}", SizeInput, parsed);
                match parsed.parse::<usize>() {
                    Ok(output) => {
                        debug!("[ {:?} ] String parsed correctly. output: {}", SizeInput, output);
                        total_size = output;
                        debug!("[ {:?} ] secret_size assigned value: {}", SizeInput, total_size);
                        state_machine = OutcomesInput;
                        debug!("[ {:?} ] Protocol transitioned to state 'OutcomesInput'.", SizeInput)
                    }
                    Err(e) => {
                        error!("Input is not a positive number! Please try again.");
                        debug!("[ {:?} ] String parsed incorrectly. Error: {}", SizeInput, e);
                        total_size = 0;
                        debug!(
                            "[ {:?} ] secret_size wiped. secret_size: {}",
                            SizeInput,
                            total_size
                        );
                        debug!("[ {:?} ] Protocol transitioned to state 'SizeInput'.", SizeInput);
                    }
                }
            }
            OutcomesInput => {
                println!("--------------------------------------------------");
                debug!("[ {:?} ] Displaying request for orderings bitstring.", OutcomesInput);
                debug!("[ {:?} ] total_size set to {}", OutcomesInput, 2 * total_size);
                println!(
                    "Please enter the MEASUREMENT OUTCOME bitstring. You will need\n\
                          to provide {} bytes, in binary form. You will be\n\
                          asked for one byte at a time. Do not use any special\n\
                          characters. Only strings consisting of 0s and 1s, of\n\
                          maximum length 8, are allowed.",
                    2 * total_size
                );
                println!("EXAMPLE:");
                println!("Please provide byte 0:");
                println!("01001110");
                println!("-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~");
                let mut i = 0;
                while i < (2 * total_size) {
                    println!(
                        "OUTCOME bytes already provided (in hex notation): {:x?}",
                        plain_data.outcomes
                    );
                    println!("Please provide byte {}:", i);
                    let parsed: String = read!("{}\n");
                    debug!("[ {:?} ] String captured. string: {}", OutcomesInput, parsed);
                    if parsed.len() > 8 {
                        error!("Maximum number of characters per string is 8, you entered {}. Try again!", parsed.len());
                    } else {
                        match u8::from_str_radix(&parsed, 2) {
                            Err(e) => {
                                error!("Not a valid bitstring! Try again!");
                                debug!("[ {:?} ] Error: {}", OutcomesInput, e);
                            }
                            Ok(result) => {
                                plain_data.outcomes.push(result);
                                debug!("[ {:?} ] New valued pushed.: {}", OutcomesInput, result);
                                i += 1;
                            }
                        }
                    }
                }
                debug!(
                    "[ {:?} ] Exited while loop. orderings: {:x?}",
                    OutcomesInput,
                    plain_data.outcomes
                );
                state_machine = Output;
                debug!("[ {:?} ] Protocol transitioned to state 'Output'.", OutcomesInput);
            }
            Output => {
                println!("--------------------------------------------------");
                debug!("[ {:?} ] Displaying greeting message.", Output);
                println!("Thank you for having provided all the needed information.");
                match plain_data.serialize() {
                        Ok(result) => {
                            debug!("Data is valid and has been serialized correctly. It will now be displayed.");
                            println!("Your data has been validated and correctly serialized. Here it is!");
                            println!();
                            println!("{}",result);
                            println!();
                            println!("Use it as you see fit. Have a nice day!");
                        }
                        Err(e) => error!("Something went wrong while serializing data. Error: {:?}. Please try again!", e)
                };
                break;
            }
        }
    }
    debug!("We are out of the main loop.");
}