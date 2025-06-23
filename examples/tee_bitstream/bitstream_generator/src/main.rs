#![no_std]
#![no_main]

// AES PASSWORD TO COMMUNICATE WITH THE TEE
const SHARED_SECRET: &[u8] = "SUp4SeCp@sSw0rd".as_bytes();

//59512135d326918f7187e6979e6fd9ddb173a4f1e4c5b8db0c8e3486511006cf21ef7a38715b4867fb63bed675cfff8581e8460b6487175ec896d6acf193dae322402137ea3381098c0c5621bdcdbc9aa7aaa22ec69c7e553a3e65443139bf7de47a0b273df1bc745f3665b7c7ac650b

//////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////

extern crate alloc; // no_std requires a custom allocator
use alloc::vec;
use alloc::vec::Vec; // Needed for buffer manipulation

use hex::{self, decode};

// Logging, printing etc.
use defmt::{debug, info, error, println, Format};
use esp_backtrace as _;
use esp_println as _;

use esp_hal::{
    aes::{Aes, Mode},
    clock::CpuClock,
    gpio::{Input, InputConfig, Level, Output, OutputConfig, Pull},
    main,
    peripherals::TIMG0,
    rng::Trng,
    sha::Sha,
    time::Duration,
    timer::timg::{MwdtStage, TimerGroup, Wdt},
    usb_serial_jtag::UsbSerialJtag
};

use zeroize::Zeroize; // Rewrite memory locations with 0s after drop, useful for security reasons

// Finally the only meaningful thing in a sea of boilerplate
use conjugate_coding::conjugate_coding::ConjugateCodingPrepare;

mod bit_ops;
mod heap_stuff;
mod cryptography;
mod conjugate_coding_helpers;

mod generator;
  
//////////////
// WATCHDOG //
//////////////
// Feed the watchog timer
fn watchdog_feed(mut wdt: Wdt<TIMG0>, state: StateMachine) -> Wdt<TIMG0> {
    wdt.feed();
    debug!("[ {:?} ] Watchdog fed.", state);
    return wdt;
}

mod serial_comms;


///////////////////
// State Machine //
///////////////////
#[derive(Format)]
enum StateMachine {
    InitDialog,   // User is asked to provide preparation data.
    InitInput,    // Preparation data is provided.
    Generate,     // User is asked to provide program input.
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
    
    let running_pin      =  Input::new(peripherals.GPIO20, InputConfig::default().with_pull(Pull::Down));
    let basis_select_pin =  Input::new(peripherals.GPIO19, InputConfig::default().with_pull(Pull::Down));
    let mut sending_pin     = Output::new(peripherals.GPIO21, Level::Low, OutputConfig::default());    
    let mut herald_pin      = Output::new(peripherals.GPIO22, Level::Low, OutputConfig::default());    
    let mut outcome0_pin    = Output::new(peripherals.GPIO16, Level::Low, OutputConfig::default());    
    let mut outcome1_pin    = Output::new(peripherals.GPIO17, Level::Low, OutputConfig::default());    

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
    let mut trng = Trng::new(peripherals.RNG, peripherals.ADC1);

    ///////////////////
    // STATE MACHINE //
    ///////////////////
    use crate::StateMachine::{
        InitDialog, InitInput, Generate,
    };
    let mut state_machine = InitDialog;
    info!("Protocol state machine initialized.");

    //////////////////////
    // CONJUGATE CODING //
    //////////////////////
    let mut preparation = ConjugateCodingPrepare::default();

    ///////////////
    // MAIN LOOP //
    ///////////////
    info!("Entering main loop...");
    loop {
        match state_machine {
            InitDialog => {
                println!("======================================================================");
                println!("This is TEE-Rust.");
                println!("The following example uses an ESP32-C6 as a bitstream generator.");
                println!("======================================================================");
                println!("[ INIT ] The generator is initializing.");
                println!(
                    "[ INIT ] Please provide the preparation information in JSON format."
                );
                println!("[ INIT ] Backspace works normally.");
                println!(
                    "[ INIT ] ENTER is not send. You can press ENTER to go to a new line."
                );
                println!("[ INIT ] Press CTRL+D (UTF8 0004, EOT) to submit information.");
                println!("");
                wdt = watchdog_feed(wdt, InitDialog);
                state_machine = InitInput;
                dbg_state_transition(InitDialog, InitInput);
            }
            InitInput => {
                let buffer = serial_comms::store_serial_buffer(&mut buffer, &mut usb_serial);
                if (buffer.len() > 0) && buffer[buffer.len() - 1] == 04 {
                    println!("");
                    println!("[ INIT ] Information submitted. Decripting...");
                    debug!("[ {:?} ] Buffer: {=[u8]:x}", InitInput, buffer);
                    buffer.pop();
                    debug!(
                        "[ {:?} ] Got rid of EOT char. New buffer: {=[u8]:x}",
                        InitInput, buffer
                    );
                    let mut decrypted_buffer = 
                        cryptography::aes256(&mut decode(&buffer).unwrap(), Mode::Decryption256, &mut aes, &mut sha, SHARED_SECRET);
                    buffer.zeroize();
                    debug!(
                        "[ {:?} ] Buffer has been zeroized: New buffer: {=[u8]:x}",
                        InitInput, buffer
                    );
                    debug!(
                        "[ {:?} ] stripping padding 0s from decrypted_buffer",
                        InitInput
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
                        InitInput, decrypted_buffer
                    );
                    println!("[ PREPARATION ] Information decrypted. Validating...");
                    match conjugate_coding_helpers::ConjugateCodingPreparePlaintext::deserialize(&decrypted_buffer) {
                        Err(_) => {
                            error!("[ INIT ] Protocol wasn't able to parse the string. Restarting generator...");
                            decrypted_buffer.zeroize();
                            debug!(
                                "[ {:?} ] decrypted_buffer has been zeroized: New decrypted_buffer: {=[u8]:x}",
                                InitInput, decrypted_buffer
                            );
                            state_machine = InitDialog;
                            dbg_state_transition(InitInput, InitDialog);
                        }
                        Ok(mut deserialized_buffer) => {
                            println!("[ INIT ] JSON input is of the right format. Validating information...");
                            debug!(
                                "[ {:?} ] deserialized_buffer: {:?}",
                                InitInput, deserialized_buffer
                            );
                            decrypted_buffer.zeroize();
                            debug!(
                                "[ {:?} ] decrypted_buffer has been zeroized: New decrypted_buffer: {=[u8]:x}",
                                InitInput, decrypted_buffer
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
                                    error!("[ INIT ] Information validation failed with error:\n      \
                                            {:?}. \
                                            Restarting protocol...", e);
                                    state_machine = Generate;
                                    dbg_state_transition(InitInput, Generate);
                                }
                                Ok(result) => {
                                    println!("[ INIT ] Information validated.");
                                    preparation = result;
                                    debug!(
                                        "[ {:?} ] Preparation struct assigned.",
                                        InitInput
                                    );
                                    state_machine = Generate;
                                    dbg_state_transition(InitInput, Generate);
                                }
                            }
                            deserialized_buffer.zeroize();
                            debug!(
                            "[ {:?} ] deserialized_buffer has been zeroized: New decrypted_buffer: {:?}",
                            InitInput, deserialized_buffer
                        );
                        }
                    };
                    wdt = watchdog_feed(wdt, InitInput);
                }
            }
            Generate => {
                generator::real(&mut trng, &preparation, &running_pin, &basis_select_pin, &mut sending_pin, &mut herald_pin, &mut outcome0_pin, &mut outcome1_pin);
            }
        }
    }
}