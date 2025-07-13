#![no_std]
#![no_main]

// AES PASSWORD TO COMMUNICATE WITH THE TEE
const SHARED_SECRET: &[u8] = "SUp4SeCp@sSw0rd".as_bytes();

const SECRET_KEY: [u8;32] = [
    0xac,
    0x09,
    0x74,
    0xbe,
    0xc3,
    0x9a,
    0x17,
    0xe3,
    0x6b,
    0xa4,
    0xa6,
    0xb4,
    0xd2,
    0x38,
    0xff,
    0x94,
    0x4b,
    0xac,
    0xb4,
    0x78,
    0xcb,
    0xed,
    0x5e,
    0xfc,
    0xae,
    0x78,
    0x4d,
    0x7b,
    0xf4,
    0xf2,
    0xff,
    0x80,
];
//59512135d326918f7187e6979e6fd9ddb173a4f1e4c5b8db0c8e3486511006cf21ef7a38715b4867fb63bed675cfff8581e8460b6487175ec896d6acf193dae322402137ea3381098c0c5621bdcdbc9aa7aaa22ec69c7e553a3e65443139bf7de47a0b273df1bc745f3665b7c7ac650b

// Here you can feed your program to the TEE!
use libsecp256k1::{Message, SecretKey, Signature, sign}; //To produce the signed output in this specific application
fn your_program_here(program_input: &Vec<u8>,  sha: &mut Sha<'_>) -> Vec<u8> {
    debug!(
        "[ your_program_here ] program input: {=[u8]:x}",
         program_input
    );
    use alloc::string::String;
    let message: [u8;32] =  
        hex::decode(
        String::from_utf8(program_input.to_vec())
            .unwrap()
            .trim_start_matches("0x")
        )
        .unwrap()
        .try_into()
        .unwrap();

    println!(
        "Message: {:?}", message
    );
    let message =  Message::parse(&message);
    let secret_key = SecretKey::parse_slice(&SECRET_KEY).unwrap();
    let (signature, recovery_id) = sign(&message, &secret_key);
    debug!("SecretKey: {:?}", SECRET_KEY);
    println!("R: {:?}", signature.r.b32());
    println!("S: {:?}", signature.s.b32());
    println!("V: {:?}", recovery_id.serialize());
    return Signature::serialize(&signature).to_vec();
}

//////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////

extern crate alloc; // no_std requires a custom allocator
use alloc::vec;
use alloc::vec::Vec; // Needed for buffer manipulation

use hex::{self, decode};

// Logging, printing etc.
use defmt::{trace, debug, info, warn, error, println, Format};
use esp_backtrace as _;
use esp_println as _;

use esp_hal::{
    aes::{Aes, Mode},
    clock::CpuClock,
    gpio::{Event, Input, InputConfig, Io, Level, Output, OutputConfig, Pull},
    main,
    peripherals::TIMG0,
    sha::Sha,
    time::Duration,
    timer::timg::{MwdtStage, TimerGroup, Wdt},
    usb_serial_jtag::UsbSerialJtag
};

use zeroize::Zeroize; // Rewrite memory locations with 0s after drop, useful for security reasons

// Finally the only meaningful thing in a sea of boilerplate
use conjugate_coding::{
    conjugate_coding::ConjugateCodingMeasure, 
    conjugate_coding::ConjugateCodingPrepare, 
    conjugate_coding::ConjugateCodingResult,
};

mod bit_ops;
    use bit_ops::{read_nth_bit, write_nth_bit};
mod heap_stuff;
mod cryptography;
mod conjugate_coding_helpers;
mod serial_comms;
mod interrupts;
    use interrupts::{
        HERALD_PIN, 
        HERALD_SEEN, 
        RECEIVING_PIN, 
        RECEIVING_STATUS, 
        OUTCOME0_PIN, 
        OUTCOME0_SEEN, 
        OUTCOME1_PIN, 
        OUTCOME1_SEEN, 
        CYCLE, 
        set_basis
    };

//////////////
// WATCHDOG //
//////////////
// Feed the watchog timer
fn watchdog_feed(mut wdt: Wdt<TIMG0>, state: StateMachine) -> Wdt<TIMG0> {
    wdt.feed();
    debug!("[ {:?} ] Watchdog fed.", state);
    return wdt;
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

// Display debug messages
fn dbg_state_transition(state1: StateMachine, state2: StateMachine) {
    debug!(
        "[ {:?} ] Protocol transitioned to state '{}'",
        state1, state2
    );
}

#[main] //Placed in RAM for faster execution
fn main() -> ! {
    info!("Bootstrapping TEE-Rust.");

    ////////////////
    // HEAP STUFF //
    ////////////////
    // Here we initialize the heap and the peripherals
    heap_stuff::init_heap();
    info!("Heap initialized.");
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);
    info!("Peripherals initialized.");

    ///////////////
    // I/O STUFF //
    ///////////////
    info!("Initializing pins.");    
    let mut io = Io::new(peripherals.IO_MUX);
    io.set_interrupt_handler(interrupts::handler);
    
    let mut running_pin = Output::new(peripherals.GPIO20, Level::Low, OutputConfig::default());    
    let mut basis_select_pin = Output::new(peripherals.GPIO19, Level::Low, OutputConfig::default());
    let receiving_pin = Input::new(peripherals.GPIO21, InputConfig::default().with_pull(Pull::Down));
    let herald_pin = Input::new(peripherals.GPIO22, InputConfig::default().with_pull(Pull::Down));
    let outcome0_pin = Input::new(peripherals.GPIO16, InputConfig::default().with_pull(Pull::Down));
    let outcome1_pin = Input::new(peripherals.GPIO17, InputConfig::default().with_pull(Pull::Down));

    //////////////
    // WATCHDOG //
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
    wdt.set_timeout(MwdtStage::Stage0, Duration::from_secs(timeout_seconds)); // Watchdog triggers after n secs of inactivity
    info!("Timeout set to {} seconds.", timeout_seconds);
    wdt.enable(); // We enable the damn thing
    info!("Watchdog enabled.");

    ////////////////
    // INTERRUPTS //
    ////////////////
    // Referencing pins to static variables so that the interrupt handler can use them
    critical_section::with(|initialize_sec| {
        RECEIVING_PIN.borrow_ref_mut(initialize_sec).replace(receiving_pin);
        HERALD_PIN.borrow_ref_mut(initialize_sec).replace(herald_pin);
        OUTCOME0_PIN.borrow_ref_mut(initialize_sec).replace(outcome0_pin);
        OUTCOME1_PIN.borrow_ref_mut(initialize_sec).replace(outcome1_pin);
    });

    //////////////////
    // SERIAL COMMS //
    //////////////////
    let mut usb_serial = UsbSerialJtag::new(peripherals.USB_DEVICE);
    info!("JTAG interface initialized.");
    let mut buffer: Vec<u8> = alloc::vec![0;0];
    info!("Console buffer initialized.");

    //////////////////
    // CRYPTOGRAPHY //
    //////////////////
    let mut sha: Sha<'_> = Sha::new(peripherals.SHA);
    let mut aes: Aes<'_> = Aes::new(peripherals.AES);

    ///////////////////
    // STATE MACHINE //
    ///////////////////
    use crate::StateMachine::{
        ComputeSecret, MeasurementDialog, MeasurementInput, PreparationDialog, PreparationInput,
        ProgramDialog, ProgramInput, RunProgram,
    };
    let mut state_machine = PreparationDialog;
    info!("Protocol state machine initialized.");

    //////////////////////
    // CONJUGATE CODING //
    //////////////////////
    let mut preparation = ConjugateCodingPrepare::default();
    let mut measurement = ConjugateCodingMeasure::default();

    /////////////////////
    // OTHER VARIABLES //
    /////////////////////
    let mut program_input: Vec<u8> = vec![0; 0];
    let mut program_hash: Vec<u8> = vec![0; 0];

    ///////////////
    // MAIN LOOP //
    ///////////////
    info!("Entering main loop...");
    loop {
        match state_machine {
            PreparationDialog => {
                println!("======================================================================");
                println!("This is TEE-Rust.");
                println!("The following example uses an ESP32-C6 as an encrypted enclave.");
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
                println!("======================================================================");
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
                let buffer = serial_comms::store_serial_buffer(&mut buffer, &mut usb_serial);
                if (buffer.len() > 0) && buffer[buffer.len() - 1] == 04 {
                    println!("");
                    println!("[ PREPARATION ] Information submitted. Decripting...");
                    debug!("[ {:?} ] Buffer: {=[u8]:x}", PreparationInput, buffer);
                    buffer.pop();
                    debug!(
                        "[ {:?} ] Got rid of EOT char. New buffer: {=[u8]:x}",
                        PreparationInput, buffer
                    );
                    let mut decrypted_buffer = 
                        cryptography::aes256(&mut decode(&buffer).unwrap(), Mode::Decryption256, &mut aes, &mut sha, SHARED_SECRET);
                    buffer.zeroize();
                    debug!(
                        "[ {:?} ] Buffer has been zeroized: New buffer: {=[u8]:x}",
                        PreparationInput, buffer
                    );
                    debug!(
                        "[ {:?} ] stripping padding 0s from decrypted_buffer",
                        PreparationInput
                    );
                    if decrypted_buffer.len() > 0 {
                        while decrypted_buffer[decrypted_buffer.len() - 1] == 0 {
                            decrypted_buffer.pop();
                            if decrypted_buffer.len() == 0 {
                                break;
                            };
                        }
                    }
                    debug!(
                        "[ {:?} ] Stripping completed. New decrypted_buffer: {=[u8]:x}",
                        PreparationInput, decrypted_buffer
                    );
                    println!("[ PREPARATION ] Information decrypted. Validating...");
                    match conjugate_coding_helpers::ConjugateCodingPreparePlaintext::deserialize(&decrypted_buffer) {
                        Err(_) => {
                            error!("[ PREPARATION ] Protocol wasn't able to parse the string. Restarting protocol...");
                            decrypted_buffer.zeroize();
                            debug!(
                                "[ {:?} ] decrypted_buffer has been zeroized: New decrypted_buffer: {=[u8]:x}",
                                PreparationInput, decrypted_buffer
                            );
                            state_machine = PreparationDialog;
                            dbg_state_transition(PreparationInput, PreparationDialog);
                        }
                        Ok(mut deserialized_buffer) => {
                            println!("[ PREPARATION ] JSON input is of the right format. Validating information...");
                            debug!(
                                "[ {:?} ] deserialized_buffer: {:?}",
                                PreparationInput, deserialized_buffer
                            );
                            decrypted_buffer.zeroize();
                            debug!(
                                "[ {:?} ] decrypted_buffer has been zeroized: New decrypted_buffer: {=[u8]:x}",
                                PreparationInput, decrypted_buffer
                            );
                            match ConjugateCodingPrepare::from_plaintext(
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
                            deserialized_buffer.zeroize();
                            debug!(
                            "[ {:?} ] deserialized_buffer has been zeroized: New decrypted_buffer: {:?}",
                            PreparationInput, deserialized_buffer
                        );
                        }
                    };
                    wdt = watchdog_feed(wdt, PreparationInput);
                }
            }
            ProgramDialog => {
                println!("[ PROGRAM INPUT ] Please provide the input to your program.");
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
                let buffer = serial_comms::store_serial_buffer(&mut buffer, &mut usb_serial);
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
                    program_hash = cryptography::hash256(buffer, &mut sha)[0..preparation.total_size].to_vec();
                    //program_hash = hash256(buffer, &mut sha)[0..8].to_vec();
                    buffer.zeroize();
                    debug!(
                        "[ {:?} ] Buffer has been zeroized: New buffer: {=[u8]:x}",
                        ProgramInput, buffer
                    );
                    debug!("[ {:?} ] program_hash assigned.", ProgramInput);
                    println!(
                        "[ PROGRAM INPUT ] Program input hash computed. \
                              The program input hash determines the choices of \
                              basis for the quantum measurement. These are:"
                    );
                    println!("");
                    println!("{=[u8]:08b}", program_hash);
                    println!("{=[u8]:x}", program_hash);
                    println!("");
                    wdt = watchdog_feed(wdt, MeasurementInput);
                    state_machine = MeasurementDialog;
                    dbg_state_transition(ProgramInput, MeasurementDialog);
                }
            }
            MeasurementDialog => {
                println!("[ MEASUREMENT ] The protocol is in measurement phase.");
                println!(
                    "[ MEASUREMENT ] Measurement information will be automatically acquired by the TEE."
                );
                wdt = watchdog_feed(wdt, MeasurementDialog);
                state_machine = MeasurementInput;
                dbg_state_transition(MeasurementDialog, MeasurementInput);
            }
            MeasurementInput => {
                debug!(
                    "[ {:?} ] Defining outcomes and success vectors.",
                    MeasurementInput
                );
                let mut outcomes: Vec<u8> = vec![];
                let mut success: Vec<u8> = vec![];
                let mut outcomes_byte: u8 = 0;
                let mut success_byte: u8 = 0;
                let mut next_cycle = 1;
                // We set up and start the acquisition here
                critical_section::with(|initialize_sec| {
                    // Attach interrupts
                    debug!(
                        "[ {:?} ] Attaching interrupts.",
                        MeasurementInput
                    );
                    let mut receiving_pin = RECEIVING_PIN.borrow_ref_mut(initialize_sec);
                    let receiving_pin = receiving_pin.as_mut().unwrap();
                    let mut herald_pin = HERALD_PIN.borrow_ref_mut(initialize_sec);
                    let herald_pin = herald_pin.as_mut().unwrap();
                    let mut outcome0_pin = OUTCOME0_PIN.borrow_ref_mut(initialize_sec);
                    let outcome0_pin = outcome0_pin.as_mut().unwrap();
                    let mut outcome1_pin = OUTCOME1_PIN.borrow_ref_mut(initialize_sec);
                    let outcome1_pin = outcome1_pin.as_mut().unwrap();
                    let cycle = CYCLE.borrow(initialize_sec);
                    debug!(
                        "[ {:?} ] Interrupts attached.",
                        MeasurementInput
                    );
                    cycle.set(0);
                    debug!(
                        "[ {:?} ] Cycle: {:?}.",
                        MeasurementInput,
                        cycle.get()
                    );
                    receiving_pin.listen(Event::AnyEdge);
                    herald_pin.listen(Event::RisingEdge);
                    outcome0_pin.listen(Event::RisingEdge);
                    outcome1_pin.listen(Event::RisingEdge);
                    debug!(
                        "[ {:?} ] Setting basis.",
                        MeasurementInput
                    );
                    set_basis(initialize_sec, &mut basis_select_pin, read_nth_bit(program_hash[0], 0));
                    debug!(
                        "[ {:?} ] Basis: {:?}.",
                        MeasurementInput,
                        read_nth_bit(program_hash[cycle.get()/16], cycle.get()/2 % 8)
                    );
                    running_pin.set_high();
                });
                while critical_section::with(|initialize_sec| { CYCLE.borrow(initialize_sec).get() < 16 * preparation.total_size}) {
                //while critical_section::with(|initialize_sec| { CYCLE.borrow(initialize_sec).get() < 127 }) {
                    critical_section::with(|while_sec| {
                        // If we're not receiving, a whole cycle has completed and
                        // We can store values.
                        if !RECEIVING_STATUS.borrow(while_sec).get() {
                            trace!(
                                "[ {:?} ] Cycle concluded, assigning inputs.",
                                MeasurementInput
                            );
                            let cycle = CYCLE.borrow(while_sec).get();
                            if cycle == next_cycle {
                                let cycle = cycle -1;
                                debug!(
                                    "[ {:?} ] Cycle: {:?}.",
                                    MeasurementInput,
                                    cycle
                                );
                                next_cycle += 1;
                                if cycle % 8 == 0 {
                                    debug!(
                                        "[ {:?} ] New byte started.",
                                        MeasurementInput
                                    );
                                    outcomes_byte = 0;
                                    success_byte = 0;
                                } else {
                                    debug!(
                                        "[ {:?} ] Modifying byte in the outcome/success vector.",
                                        MeasurementInput
                                    );
                                    outcomes_byte = outcomes.pop().unwrap();
                                    success_byte = success.pop().unwrap();
                                    debug!(
                                        "[ {:?} ] outcomes_byte: 0b{:08b}.",
                                        MeasurementInput,
                                        outcomes_byte
                                    );
                                    debug!(
                                        "[ {:?} ] success_byte: 0b{:08b}.",
                                        MeasurementInput,
                                        success_byte
                                    );
                                }
                                let herald_seen = HERALD_SEEN.borrow(while_sec);
                                let outcome0_seen = OUTCOME0_SEEN.borrow(while_sec);
                                let outcome1_seen = OUTCOME1_SEEN.borrow(while_sec);
                                if herald_seen.get() && (outcome0_seen.get() ^ outcome1_seen.get()) {
                                    outcomes_byte = write_nth_bit(outcomes_byte, cycle % 8 , outcome1_seen.get());
                                    success_byte = write_nth_bit(success_byte, cycle % 8 , true);
                                } else {
                                    success_byte = write_nth_bit(success_byte, cycle % 8, false);
                                }
                                debug!(
                                    "[ {:?} ] herald_seen: {:?}.",
                                    MeasurementInput,
                                    herald_seen
                                );
                                debug!(
                                    "[ {:?} ] outcome0_seen: {:?}.",
                                    MeasurementInput,
                                    outcome0_seen
                                );
                                debug!(
                                    "[ {:?} ] outcome1_seen: {:?}.",
                                    MeasurementInput,
                                    outcome1_seen
                                );
                                debug!(
                                    "[ {:?} ] outcomes_byte: 0b{:08b}.",
                                    MeasurementInput,
                                    outcomes_byte
                                );
                                debug!(
                                    "[ {:?} ] success_byte: 0b{:08b}.",
                                    MeasurementInput,
                                    success_byte
                                );
                                outcomes.push(outcomes_byte);
                                success.push(success_byte);
                                debug!(
                                    "[ {:?} ] outcomes: {=[u8]:08b}.", 
                                    MeasurementInput,
                                    outcomes
                                );
                                debug!(
                                    "[ {:?} ] success: {=[u8]:08b}.",
                                    MeasurementInput,
                                    success
                                );
                                // Here we change basis every couple of qubits measured.
                                if cycle % 2 == 0 {
                                    debug!(
                                        "[ {:?} ] Chainging basis.",
                                        MeasurementInput
                                    );
                                    debug!(
                                        "[ {:?} ] Basis: {:?}.",
                                        MeasurementInput,
                                        read_nth_bit(program_hash[cycle/16], cycle/2 % 8)
                                    );
                                    set_basis(while_sec, &mut basis_select_pin, read_nth_bit(program_hash[cycle/16], cycle/2 % 8));
                                }
                            }
                        }
                    });
                }
                // Here we detach interrupts and set the running pin to low
                critical_section::with(|deinitialize_sec| {
                    // Detach interrupts
                    debug!(
                        "[ {:?} ] Detaching interrupts.",
                        MeasurementInput
                    );
                    let mut receiving_pin = RECEIVING_PIN.borrow_ref_mut(deinitialize_sec);
                    let receiving_pin = receiving_pin.as_mut().unwrap();
                    let mut herald_pin = HERALD_PIN.borrow_ref_mut(deinitialize_sec);
                    let herald_pin = herald_pin.as_mut().unwrap();
                    let mut outcome0_pin = OUTCOME0_PIN.borrow_ref_mut(deinitialize_sec);
                    let outcome0_pin = outcome0_pin.as_mut().unwrap();
                    let mut outcome1_pin = OUTCOME1_PIN.borrow_ref_mut(deinitialize_sec);
                    let outcome1_pin = outcome1_pin.as_mut().unwrap();
                    receiving_pin.unlisten();
                    herald_pin.unlisten();
                    outcome0_pin.unlisten();
                    outcome1_pin.unlisten();
                    running_pin.set_low();
                });                
                debug!(
                    "[ {:?} ] outcomes: {=[u8]:08b}.",
                    MeasurementInput,
                    outcomes
                );
                debug!(
                    "[ {:?} ] success: {=[u8]:08b}.",
                    MeasurementInput,
                    success
                );
                match ConjugateCodingMeasure::from_plaintext(
                    &preparation,
                    outcomes.clone(),
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
                outcomes.zeroize();
                success.zeroize();
                wdt = watchdog_feed(wdt, MeasurementInput);
            }
            ComputeSecret => {
                println!("======================================================================");
                println!("[ RESULT ] I'm now using the information provided to compute a result.");
                match ConjugateCodingResult::new(&preparation, &measurement, 1) {
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
                println!("Program result: {:?}", your_program_here(&program_input, & mut sha));
                println! {""};
                println! {"Bye! Restarting protocol..."}
                state_machine = PreparationInput;
                dbg_state_transition(RunProgram, PreparationInput);
            }
        }
    }
}