#![no_std]
#![no_main]

extern crate alloc; // no_std requires a custom allocator
use alloc::vec;
use alloc::vec::Vec; // Needed for buffer manipulation

use alloc::string::String;
use hex;
use serde::de::Error;

use core::ptr::addr_of_mut; // Needed to initialize heap

// Logging, printing etc.
use defmt::{debug, error, info, println, trace, Format};
use esp_backtrace as _;
use esp_println as _;

use esp_hal::{
    // aes::Aes,        // AES ecnryption-decryption scheme
    // aes::Mode,       // AES mode (128, 256, etc)
    clock::CpuClock,
    main,
    peripherals::TIMG0,
    sha::{Sha, Sha256},
    time::Duration,
    timer::timg::{MwdtStage, TimerGroup, Wdt},
    usb_serial_jtag::UsbSerialJtag, // Needed to communicate over USB
};

use nb::block;

// Rewrite memory locations with 0s after drop, useful for security reasons
use zeroize::{Zeroize, ZeroizeOnDrop};

use core::result::Result;
use serde::{Deserialize, Deserializer}; // We do like our JSON very much

// Finally the only meaningful thing in a sea of boilerplate
use conjugate_coding;
use conjugate_coding::conjugate_coding::{
    ConjugateCodingMeasure, ConjugateCodingPrepare, ConjugateCodingResult,
};

fn init_heap() {
    // Function to initialize the heap memory
    const HEAP_SIZE: usize = 128 * 1024;
    static mut HEAP: core::mem::MaybeUninit<[u8; HEAP_SIZE]> = core::mem::MaybeUninit::uninit();
    unsafe {
        esp_alloc::HEAP.add_region(esp_alloc::HeapRegion::new(
            addr_of_mut!(HEAP) as *mut u8,
            HEAP_SIZE,
            esp_alloc::MemoryCapability::Internal.into(),
        ));
    }
}

///////////////////
// State Machine //
///////////////////
#[derive(Format)]
enum StateMachine {
    PreparationDialog, // User is asked to provide preparation data.
    PreparationInput,  // Preparation data is provided.
    ProgramDialog,     // User is asked to provide program input.
    ProgramInput,      // Input data is provided.
    MeasurementDialog, // User is asked to provide measurement data.
    MeasurementInput,  // Measurement data is provided.
    ComputeSecret,     // The actual security protocol is run.
    RunProgram,        // The program is unlocked and ran.
}

#[main]
fn main() -> ! {
    info!("Bootstrapping TEE-Rust.");

    ////////////////
    // HEAP STUFF //
    ////////////////
    // Here we initialize the heap and the peripherals
    init_heap();
    info!("Heap initialized.");
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);
    info!("Peripherals initialized.");

    // Alternative config, more verbose but better to customize several options.
    // let peripherals = esp_hal::init({
    //     let mut config = esp_hal::Config::default();
    //     // Configure the CPU to run at the maximum frequency.
    //     config.cpu_clock = CpuClock::max();
    //     config
    // });

    //////////////
    // Watchdog //
    //////////////
    // Esp32 chips have a nasty watchdog
    // that decides to kill your program
    // if the same task runs for too long.
    // Here we create a watchdog and constanly
    // feed it to avoid this.
    let timg0 = TimerGroup::new(peripherals.TIMG0); // Create a new timer
    info!("Watchdog timer created.");
    let mut wdt = timg0.wdt; // Use it to create a new watchdog
    info!("Watchdog created");
    let timeout_seconds = 300;
    wdt.set_timeout(MwdtStage::Stage0, Duration::secs(timeout_seconds)); // Watchdog triggers after n secs of inactivity
    info!("Timeout set to {} seconds.", timeout_seconds);
    wdt.enable(); // We enable the damn thing
    info!("Watchdog enabled.");

    //////////////////
    // Serial Comms //
    //////////////////
    let mut usb_serial = UsbSerialJtag::new(peripherals.USB_DEVICE);
    info!("JTAG interface initialized.");
    let mut buffer: Vec<u8> = alloc::vec![0;0];
    info!("Consol buffer initialized.");

    //////////////////
    // CRYPTOGRAPHY //
    //////////////////
    let mut sha = Sha::new(peripherals.SHA);
    let mut hasher = sha.start::<Sha256>();

    //////////////////////////////
    // Conjugate Coding Helpers //
    //////////////////////////////
    // Custom deserializer for Vec<u8> from hex string
    fn deserialize_vec_from_hex_string<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(Error::custom)
    }
    #[derive(Zeroize, ZeroizeOnDrop, Deserialize, Format)]
    pub struct ConjugateCodingPreparePlaintext {
        security_size: usize,
        orderings: Vec<u8>,
        security0: Vec<u8>,
        security1: Vec<u8>,
    }

    impl ConjugateCodingPreparePlaintext {
        fn deserialize(json_vec: &[u8]) -> Result<Self, serde_json::Error> {
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

    #[derive(Zeroize, ZeroizeOnDrop, Deserialize, Format)]
    pub struct ConjugateCodingMeasurePlaintext {
        outcomes: Vec<u8>
    }

    impl ConjugateCodingMeasurePlaintext {
        fn deserialize(json_vec: &[u8]) -> Result<Self, serde_json::Error> {
            #[derive(Deserialize)]
            struct HexPlainData {
                #[serde(deserialize_with = "deserialize_vec_from_hex_string")]
                outcomes: Vec<u8>
            }

            let hex_data: HexPlainData = serde_json::from_slice(json_vec)?;

            Ok(ConjugateCodingMeasurePlaintext {
                outcomes: hex_data.outcomes
            })
        }
    }

    let mut preparation = ConjugateCodingPrepare::new_from_zero();
    let mut measurement = ConjugateCodingMeasure::new_from_zero();

    ///////////////////
    // STATE MACHINE //
    ///////////////////
    use crate::StateMachine::{
        ComputeSecret, MeasurementDialog, MeasurementInput, PreparationDialog, PreparationInput,
        ProgramDialog, ProgramInput, RunProgram,
    };
    let mut state_machine = PreparationDialog;
    info!("Protocol state machine initialized.");

    ///////////////////
    // TEE VARIABLES //
    ///////////////////
    let mut program_input: Vec<u8> = vec![0; 0];
    let mut program_hash: Vec<u8> = vec![0; 0];

    ///////////////
    // MAIN LOOP //
    ///////////////
    info!("Entering main loop...");
    loop {
        match state_machine {
            PreparationDialog => {
                println!("This is TEE-Rust.");
                println!("[ PREPARATION ] The protocol is in preparation phase.");
                println!(
                    "[ PREPARATION ] Please provide the preparation information in JSON format."
                );
                println!("[ PREPARATION ] Backspace works normally.");
                println!(
                    "[ PREPARATION ] ENTER is not send. You can press ENTER to go to a new line."
                );
                println!("[ PREPARATION ] Press CTRL+D (UTF8 0004, EOT) to submit information.");
                println!("");
                wdt = watchdog_feed(wdt, PreparationDialog);
                state_machine = PreparationInput;
                dbg_state_transition(PreparationDialog, PreparationInput);
            }
            PreparationInput => {
                let buffer = store_serial_buffer(&mut buffer, &mut usb_serial);
                if (buffer.len() > 0) && buffer[buffer.len() - 1] == 04 {
                    println!("");
                    println!("[ PREPARATION ] Information submitted. Validating...");
                    debug!("[ {:?} ] Buffer: {=[u8]:x}", PreparationInput, buffer);
                    buffer.pop();
                    debug!(
                        "[ {:?} ] Got rid of EOT char. New buffer: {=[u8]:x}",
                        PreparationInput, buffer
                    );
                    match ConjugateCodingPreparePlaintext::deserialize(&buffer) {
                        Err(_) => {
                            error!("[ PREPARATION ] Protocol wasn't able to parse the string. Restarting protocol...");
                            buffer.zeroize();
                            debug!(
                                "[ {:?} ] Buffer has been zeroized: New buffer: {=[u8]:x}",
                                PreparationInput, buffer
                            );
                            state_machine = PreparationDialog;
                            dbg_state_transition(PreparationInput, PreparationDialog);
                        }
                        Ok(deserialized_buffer) => {
                            println!("[ PREPARATION ] JSON input is of the right format. Validating information...");
                            debug!(
                                "[ {:?} ] deserialized_buffer: {:?}",
                                PreparationInput, deserialized_buffer
                            );
                            buffer.zeroize();
                            debug!(
                                "[ {:?} ] Buffer has been zeroized: New buffer: {=[u8]:x}",
                                PreparationInput, buffer
                            );
                            debug!(
                                "[ {:?} ] checking that the preparation provides 0 secret bits",
                                PreparationInput
                            );
                            match ConjugateCodingPrepare::new_plaintext(
                                0,
                                deserialized_buffer.security_size,
                                deserialized_buffer.orderings.clone(),
                                vec![255; deserialized_buffer.security_size], //Bitmask is all 1 in this application!
                                deserialized_buffer.security0.clone(),
                                deserialized_buffer.security1.clone(),
                            ) {
                                Err(e) => {
                                    error!("[ PREPARATION ] Information validation failed with error:\n      \
                                            {:?}. \
                                            Restarting protocol...", e);
                                    state_machine = ProgramDialog;
                                    dbg_state_transition(PreparationInput, ProgramDialog);
                                }
                                Ok(result) => {
                                    println!("[ PREPARATION ] Information validated.");
                                    preparation = result;
                                    debug!(
                                        "[ {:?} ] Preparation struct assigned.",
                                        PreparationInput
                                    );
                                    state_machine = ProgramDialog;
                                    dbg_state_transition(PreparationInput, ProgramDialog);
                                }
                            }
                        }
                    };
                    wdt = watchdog_feed(wdt, PreparationInput);
                }
            }
            ProgramDialog => {
                println!("[ PROGRAM INPUT ] Please, provide the input to your program.");
                println!("[ PROGRAM INPUT ] Backspace works normally.");
                println!(
                    "[ PROGRAM INPUT ] ENTER is not send. You can press ENTER to go to a new line."
                );
                println!("[ PROGRAM INPUT ] Press CTRL+D (UTF8 0004, EOT) to submit information.");
                println!("");
                wdt = watchdog_feed(wdt, ProgramDialog);
                state_machine = ProgramInput;
                dbg_state_transition(ProgramDialog, ProgramInput);
            }
            ProgramInput => {
                let buffer = store_serial_buffer(&mut buffer, &mut usb_serial);
                if (buffer.len() > 0) && buffer[buffer.len() - 1] == 04 {
                    println!("");
                    println!("[ PROGRAM INPUT ] Information submitted.");
                    debug!("[ {:?} ] Buffer: {=[u8]:x}", ProgramInput, buffer);
                    buffer.pop();
                    debug!(
                        "[ {:?} ] Got rid of EOT char. New buffer: {=[u8]:x}",
                        ProgramInput, buffer
                    );
                    program_input = buffer.to_vec();
                    debug!("[ {:?} ] program_input assigned", ProgramInput);
                    println!("[ PROGRAM INPUT ] Computing program input hash");
                    let mut hash_buffer: &[u8] = buffer;
                    debug!("[ {:?} ] hash_buffer initialized.", ProgramInput);
                    trace!("[ {:?} ] hash_buffer: {:?}", ProgramInput, hash_buffer);
                    while !hash_buffer.is_empty() {
                        // All the HW Sha functions are infallible so unwrap is fine to use if
                        // you use block!
                        hash_buffer = block!(hasher.update(hash_buffer)).unwrap();
                        trace!("[ {:?} ] hash_buffer: {:?}", ProgramInput, hash_buffer);
                    }
                    let mut output = [0u8; 32];
                    block!(hasher.finish(output.as_mut_slice())).unwrap();
                    debug!("[ {:?} ] hash: {:?}", ProgramInput, output);
                    program_hash = output[0..preparation.total_size].to_vec();
                    buffer.zeroize();
                    debug!(
                        "[ {:?} ] Buffer has been zeroized: New buffer: {=[u8]:x}",
                        ProgramInput, buffer
                    );
                    debug!("[ {:?} ] program_hash assigned.", ProgramInput);
                    println!(
                        "[ PROGRAM INPUT ] Program input hash computed.\n\
                              The program input hash determines the choices of\n\
                              basis for the quantum measurement. These are:"
                    );
                    println!("");
                    println!("{=[u8]:b}", program_hash);
                    println!("");
                    wdt = watchdog_feed(wdt, MeasurementInput);
                    state_machine = MeasurementDialog;
                    dbg_state_transition(ProgramInput, MeasurementDialog);
                }
            }
            MeasurementDialog => {
                println!("[ MEASUREMENT ] The protocol is in measurement phase.");
                println!(
                    "[ MEASUREMENT ] Please provide the measurement information in JSON format."
                );
                println!("[ MEASUREMENT ] Backspace works normally.");
                println!(
                    "[ MEASUREMENT ] ENTER is not send. You can press ENTER to go to a new line."
                );
                println!("[ MEASUREMENT ] Press CTRL+D (UTF8 0004, EOT) to submit information.");
                println!("");
                wdt = watchdog_feed(wdt, MeasurementDialog);
                state_machine = MeasurementInput;
                dbg_state_transition(MeasurementDialog, MeasurementInput);
            }
            MeasurementInput => {
                let buffer = store_serial_buffer(&mut buffer, &mut usb_serial);
                if (buffer.len() > 0) && buffer[buffer.len() - 1] == 04 {
                    println!("");
                    println!("[ MEASUREMENT ] Information submitted. Validating...");
                    debug!("[ {:?} ] Buffer: {=[u8]:x}", MeasurementInput, buffer);
                    buffer.pop();
                    debug!(
                        "[ {:?} ] Got rid of EOT char. New buffer: {=[u8]:x}",
                        MeasurementInput, buffer
                    );
                    match ConjugateCodingMeasurePlaintext::deserialize(&buffer) {
                        Err(_) => {
                            error!("[ MEASUREMENT ] Protocol wasn't able to parse the string. Please retry.");
                            buffer.zeroize();
                            debug!(
                                "[ {:?} ] Buffer has been zeroized: New buffer: {=[u8]:x}",
                                MeasurementInput, buffer
                            );
                            state_machine = MeasurementDialog;
                            dbg_state_transition(MeasurementInput, MeasurementDialog);
                        }
                        Ok(deserialized_buffer) => {
                            println!("[ MEASUREMENT ] JSON input is of the right format. Validating information...");
                            debug!(
                                "[ {:?} ] deserialized_buffer: {:?}",
                                MeasurementInput, deserialized_buffer
                            );
                            buffer.zeroize();
                            debug!(
                                "[ {:?} ] Buffer has been zeroized: New buffer: {=[u8]:x}",
                                MeasurementInput, buffer
                            );
                            match ConjugateCodingMeasure::new_plaintext(
                                &preparation,
                                deserialized_buffer.outcomes.clone(),
                                program_hash.clone(),
                            ) {
                                Ok(result) => {
                                    println!("[ MEASUREMENT ] Information validated.");
                                    measurement = result;
                                    debug!(
                                        "[ {:?} ] Measurement struct assigned.",
                                        MeasurementInput
                                    );
                                    state_machine = ComputeSecret;
                                    dbg_state_transition(MeasurementInput, ComputeSecret);
                                }
                                Err(e) => {
                                    error!("[ MEASUREMENT ] Information validation failed with error:\n      \
                                            {:?}. \
                                            Please retry.", e);
                                    state_machine = MeasurementDialog;
                                    dbg_state_transition(MeasurementInput, MeasurementDialog);
                                }
                            }
                            program_hash.zeroize();
                        }
                    };
                    wdt = watchdog_feed(wdt, MeasurementInput);
                }
            }
            ComputeSecret => {
                println!("[ RESULT ] I'm now using the information provided to compute a result.");
                match ConjugateCodingResult::new(&preparation, &measurement) {
                    Err(e) => {
                        error!(
                            "[ RESULT ] Result computation hasn't passed security validation: {:?}",
                            e
                        );
                        error!("[ RESULT ] Restarting protocol...");
                        preparation.zeroize();
                        measurement.zeroize();
                        debug!("[ ComputeSecret ] Protocol data zeroized.");
                        state_machine = PreparationDialog;
                        dbg_state_transition(ComputeSecret, PreparationDialog);
                    }
                    Ok(_) => {
                        println!("[ RESULT ] Security verification passed! Unlocking program...");
                        state_machine = RunProgram;
                        dbg_state_transition(ComputeSecret, RunProgram);
                    }
                }
                wdt = watchdog_feed(wdt, ComputeSecret);
            }
            RunProgram => {
                wdt.feed();
                println! {""};
                println!("Program result: {:?}", your_program_here(&program_input));
                println! {""};
                println! {"Bye! Restarting protocol..."}
                state_machine = PreparationInput;
                dbg_state_transition(RunProgram, PreparationInput);
            }
        }
    }
}

// Reads from serial and returns a buffer object
fn store_serial_buffer<'a>(
    buffer: &'a mut Vec<u8>,
    usb_serial: &mut UsbSerialJtag<'_, esp_hal::Blocking>,
) -> &'a mut Vec<u8> {
    while let Result::Ok(c) = usb_serial.read_byte() {
        //trace!("Old Buffer: {=[u8]:x}", buffer);
        match c {
            0x0..0x4 | 0x05..0x08 | 0x9..0x0D | 0x0F..=0x1F | 0x80..=0xff => trace!(
                "store_serial_buffer: Special char {:x} detected. Doing nothing.",
                c
            ),
            0x4 => {
                trace!("store_serial_buffer: Special char {:x} (EOT) detected. Pushing into buffer and returning.", c);
                buffer.push(c); // Push char into buffer
            }
            0x8 => {
                trace!(
                    "store_serial_buffer: Special char {:x} (Backspace) detected.",
                    c
                );
                match buffer.pop() {
                    // Strip last char out of buffer
                    Some(_x) => {
                        trace!("store_serial_buffer: Buffer was not empyt. Last char in buffer cleared.");
                        let _ = usb_serial.write_byte_nb(c); // Display: Cursor 1 to the left
                        let _ = usb_serial.write_byte_nb(0x20); //Display: replace last char with space
                        let _ = usb_serial.write_byte_nb(c); // Display: Cursor 1 to the left again
                        usb_serial.flush_tx().ok();
                    }
                    None => trace!("store_serial_buffer: Buffer was already empty!"),
                }
            }
            0x0D => {
                println!("");
                trace!(
                    "store_serial_buffer: Special char {:x} (Newline) detected.",
                    c
                )
            }
            _ => {
                trace!(
                    "store_serial_buffer: Char {:x} detected. Adding to buffer.",
                    c
                );
                let _ = usb_serial.write_byte_nb(c); // Display: Write char
                usb_serial.flush_tx().ok();
                buffer.push(c); // Push char into buffer
            }
        }
        trace!("store_serial_buffer: New Buffer: {=[u8]:x}", buffer);
    }
    return buffer;
}

fn dbg_state_transition(state1: StateMachine, state2: StateMachine) {
    debug!(
        "[ {:?} ] Protocol transitioned to state '{}'",
        state1, state2
    );
}

fn watchdog_feed(mut wdt: Wdt<TIMG0>, state: StateMachine) -> Wdt<TIMG0> {
    wdt.feed();
    debug!("[ {:?} ] Watchdog fed.", state);
    return wdt;
}

fn your_program_here(_program_input: &Vec<u8>) -> Vec<u8> {
    return vec![0; 0];
}

// let mut aes = Aes::new(peripherals.AES);

// // Hardcoded keys are obviously insecure. Consider this just an example!
// let keytext = "SUp4SeCp@sSw0rd".as_bytes();
// let plaintext = "message".as_bytes();

// // create an array with aes128 key size
// let mut keybuf = [0_u8; 32];
// keybuf[..keytext.len()].copy_from_slice(keytext);

// // create an array with aes block size
// let mut block_buf = [0_u8; 16];
// block_buf[..plaintext.len()].copy_from_slice(plaintext);

// let mut block = block_buf.clone();
// aes.process(&mut block, Mode::Encryption256, keybuf);
// let hw_encrypted = block.clone();

// aes.process(&mut block, Mode::Decryption256, keybuf);
// let hw_decrypted = block;
