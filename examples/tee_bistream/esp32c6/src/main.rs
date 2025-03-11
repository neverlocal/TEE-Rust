#![no_std]
#![no_main]

// AES PASSWORD TO COMMUNICATE WITH THE TEE
const SHARED_SECRET: &[u8] = "SUp4SeCp@sSw0rd".as_bytes();

// Here you can feed your program to the TEE!
fn your_program_here(_program_input: &Vec<u8>) -> Vec<u8> {
    return vec![0; 0];
}

//////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////

extern crate alloc; // no_std requires a custom allocator
use alloc::vec;
use alloc::vec::Vec; // Needed for buffer manipulation

use alloc::string::String;
use hex::{self, decode};
use serde::de::Error;

use core::ptr::addr_of_mut; // Needed to initialize heap

// Logging, printing etc.
use defmt::{trace, debug, info, warn, error, println, Format};
use esp_backtrace as _;
use esp_println as _;

// Variable handling in interrupts
use core::cell::{RefCell, Cell};
use critical_section::{CriticalSection, Mutex};

use esp_hal::{
    gpio::{Event, Input, Io, Level, Output, Pull},
    interrupt::InterruptConfigurable,
    handler,
    ram,
    clock::CpuClock, // Set CPU clock
    time::{self, Duration, Instant}, // Needed to manipulate watchogs
    peripherals::TIMG0, // Needed to manipulate watchogs
    timer::timg::{MwdtStage, TimerGroup, Wdt}, // Needed to manipulate watchogs
    usb_serial_jtag::UsbSerialJtag, // Needed to communicate over USB
    sha::{Sha, Sha256}, // Hashing
    aes::{Aes, Mode},       // AES ecnryption-decryption scheme
    main,
};

use nb::block; // Needed for hashing

use zeroize::{Zeroize, ZeroizeOnDrop}; // Rewrite memory locations with 0s after drop, useful for security reasons

use core::result::Result; // Manipulate errors

use serde::{Deserialize, Deserializer}; // We do like our JSON very much

// Finally the only meaningful thing in a sea of boilerplate
use conjugate_coding::{
    conjugate_coding::ConjugateCodingMeasure, 
    conjugate_coding::ConjugateCodingPrepare, 
    conjugate_coding::ConjugateCodingResult,
};

/////////////////////
// BYTE OPERATIONS //
/////////////////////
// Checks if the n-th bit of a byte is 1.
fn read_nth_bit(byte: u8, bit: usize) -> bool {
    let mask: [u8; 8] = [128, 64, 32, 16, 8, 4, 2, 1];
    byte & mask[bit] != 0
}
// Sets nth bit of a byte.
fn write_nth_bit(byte: u8, bit: usize, value: bool) -> u8 {
    let mask: u8 = 1 << (7 - bit);
    debug!("byte: 0b{:08b}", byte);
    debug!("mask: 0b{:08b}", mask);
    debug!("value: 0b{:08b}", value);
    let result: u8;
    if value {
        result = byte | mask;
        debug!("New byte: 0b{:08b}", result);
    } else {
        result = byte & !mask;
        debug!("New byte: 0b{:08b}", result);
    }
    return result;
}

////////////////
// HEAP STUFF //
////////////////
// Function to initialize the heap memory
fn init_heap() {
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

//////////////
// WATCHDOG //
//////////////
// Feed the watchog timer
fn watchdog_feed(mut wdt: Wdt<TIMG0>, state: StateMachine) -> Wdt<TIMG0> {
    wdt.feed();
    debug!("[ {:?} ] Watchdog fed.", state);
    return wdt;
}

//////////////////
// SERIAL COMMS //
//////////////////
// Reads from serial and returns a buffer object
fn store_serial_buffer<'a>(
    buffer: &'a mut Vec<u8>,
    usb_serial: &mut UsbSerialJtag<'_, esp_hal::Blocking>,
) -> &'a mut Vec<u8> {
    while let Result::Ok(c) = usb_serial.read_byte() {
        //trace!("Old Buffer: {=[u8]:x}", buffer);
        match c {
            0x0..0x4 | 0x05..0x08 | 0x9..0x0D | 0x0F..=0x1F | 0x80..=0xff => trace!(
                "[ store_serial_buffer ] Special char {:x} detected. Doing nothing.",
                c
            ),
            0x4 => {
                trace!("[ store_serial_buffer ] Special char {:x} (EOT) detected. Pushing into buffer and returning.", c);
                buffer.push(c); // Push char into buffer
            }
            0x8 => {
                trace!(
                    "[ store_serial_buffer ] Special char {:x} (Backspace) detected.",
                    c
                );
                match buffer.pop() {
                    // Strip last char out of buffer
                    Some(_x) => {
                        trace!("[ store_serial_buffer ] Buffer was not empyt. Last char in buffer cleared.");
                        let _ = usb_serial.write_byte_nb(c); // Display: Cursor 1 to the left
                        let _ = usb_serial.write_byte_nb(0x20); //Display: replace last char with space
                        let _ = usb_serial.write_byte_nb(c); // Display: Cursor 1 to the left again
                        usb_serial.flush_tx().ok();
                    }
                    None => trace!("[ store_serial_buffer ] Buffer was already empty!"),
                }
            }
            0x0D => {
                println!("");
                trace!(
                    "[ store_serial_buffer ] Special char {:x} (Newline) detected.",
                    c
                )
            }
            _ => {
                trace!(
                    "[ store_serial_buffer ] Char {:x} detected. Adding to buffer.",
                    c
                );
                let _ = usb_serial.write_byte_nb(c); // Display: Write char
                usb_serial.flush_tx().ok();
                buffer.push(c); // Push char into buffer
            }
        }
        trace!("[ store_serial_buffer ] New Buffer: {=[u8]:x}", buffer);
    }
    return buffer;
}


//////////////////
// CRYPTOGRAPHY //
//////////////////
// Compute the sha256 of an input
fn hash256(buffer: &[u8], sha: &mut Sha<'_>) -> [u8; 32] {
    let mut hasher: esp_hal::sha::ShaDigest<'_, Sha256, &mut Sha<'_>> = sha.start::<Sha256>();
    let mut hash_buffer: &[u8] = buffer;
    trace!("[ hash256 ] hash_buffer initialized.");
    trace!("[ hash256 ] hash_buffer: {=[u8]:x}", hash_buffer);
    while !hash_buffer.is_empty() {
        // All the HW Sha functions are infallible so unwrap is fine to use if
        // you use block!
        hash_buffer = block!(hasher.update(hash_buffer)).unwrap();
        trace!("[ hash256 ] hash_buffer: {=[u8]:x}", hash_buffer);
    }
    let mut output = [0u8; 32];
    block!(hasher.finish(output.as_mut_slice())).unwrap();
    trace!("[ hash256 ] hash: {=[u8]:x}", output);
    return output;
}

// Encrypt/Decrypt an input using AES
fn aes256(buffer: &mut Vec<u8>, mode: Mode, aes: &mut Aes<'_>, sha: &mut Sha<'_>) -> Vec<u8> {
    let keybuf = hash256(SHARED_SECRET, sha);
    trace!("[ aes256 ] Secret key hashed.");
    trace!("[ aes256 ] Key hash: {=[u8]:x}", keybuf);
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
        trace!("[ aes256 ] Chunk: {=[u8]:x}", chunk);
        blocks.push(chunk);
        i += 16;
    }
    trace!("[ aes256 ] Chunk vector: {:x}", blocks);
    for j in 0..blocks.len() {
        match mode {
            Mode::Encryption256 => {
                trace!("[ aes256 ] Encrypting chunk: {:?}", j);
                trace!("[ aes256 ] Decrypted chunk: {=[u8]:x}", blocks[j]);
                aes.process(&mut blocks[j], Mode::Encryption256, keybuf);
                trace!("[ aes256 ] Encrypted chunk: {=[u8]:x}", blocks[j]);
            }
            Mode::Decryption256 => {
                trace!("[ aes256 ] Decrypting chunk: {:?}", j);
                trace!("[ aes256 ] Encrypted chunk: {=[u8]:x}", blocks[j]);
                aes.process(&mut blocks[j], Mode::Decryption256, keybuf);
                trace!("[ aes256 ] Decrypted chunk: {=[u8]:x}", blocks[j]);
            }
            _ => (), // If user asks for other modes, this function is the identity and returns the plaintext.
        }
    }
    let mut flattened = Vec::new();
    trace!("[ aes256 ] Flattening chunk vector.");
    for chunk in blocks {
        flattened.extend_from_slice(&chunk);
    }
    trace!("[ aes256 ] Flattened vector: {=[u8]:x}", flattened);
    return flattened;
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


//////////////////////
// CONJUGATE CODING //
//////////////////////
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


////////////////
// INTERRUPTS //
////////////////
static RECEIVING_PIN: Mutex<RefCell<Option<Input>>> = Mutex::new(RefCell::new(None));
static HERALD_PIN: Mutex<RefCell<Option<Input>>> = Mutex::new(RefCell::new(None));
static OUTCOME0_PIN: Mutex<RefCell<Option<Input>>> = Mutex::new(RefCell::new(None));
static OUTCOME1_PIN: Mutex<RefCell<Option<Input>>> = Mutex::new(RefCell::new(None));

#[handler]
#[ram] //Placed in RAM for faster execution
fn handler() {
    critical_section::with(|receiving_sec| {
        let mut receiving_pin = RECEIVING_PIN.borrow_ref_mut(receiving_sec);
        let receiving_pin = receiving_pin.as_mut().unwrap();
        if receiving_pin.is_interrupt_set() {
            debug!("[ handler ] RECEIVING was the source of the interrupt");
            if receiving_pin.is_high() {
                start_cycle(receiving_sec);
            } else {
                stop_cycle(receiving_sec);
            }
            receiving_pin.clear_interrupt();
        }
    });

    critical_section::with(|herald_sec| {
        let mut herald_pin = HERALD_PIN.borrow_ref_mut(herald_sec);
        let herald_pin = herald_pin.as_mut().unwrap();
        if herald_pin.is_interrupt_set() {
            debug!("[ handler ] HERALD was the source of the interrupt");
            see_herald(herald_sec);
            herald_pin.clear_interrupt();
        }
    });

    critical_section::with(|outcome0_sec| {
        let mut outcome0_pin = OUTCOME0_PIN.borrow_ref_mut(outcome0_sec);
        let outcome0_pin = outcome0_pin.as_mut().unwrap();
        if outcome0_pin.is_interrupt_set() {
            debug!("[ handler ] OUTCOME0 was the source of the interrupt");
            see_outcome0(outcome0_sec);
            outcome0_pin.clear_interrupt();
        }
    });

    critical_section::with(|outcome1_sec| {
        let mut outcome1_pin = OUTCOME1_PIN.borrow_ref_mut(outcome1_sec);
        let outcome1_pin = outcome1_pin.as_mut().unwrap();
        if outcome1_pin.is_interrupt_set() {
            debug!("[ handler ] OUTCOME1 was the source of the interrupt");
            see_outcome1(outcome1_sec);
            outcome1_pin.clear_interrupt();
        }
    });
}

/////////////////////////////
// MEASUREMENT ACQUISITION //
/////////////////////////////
 
// Constants
#[ram]
static OUTCOME_DELAY_US: u64 = 500;
#[ram]
static OUTCOME_DELAY_STDDEV_US: u64 = 50;
#[ram]
static MIN_OUTCOME_DELAY_US: u64 = OUTCOME_DELAY_US-3*OUTCOME_DELAY_STDDEV_US;
#[ram]
static MAX_OUTCOME_DELAY_US: u64 = OUTCOME_DELAY_US+3*OUTCOME_DELAY_STDDEV_US;

// Variables
#[ram]
static CYCLE: Mutex<Cell<usize>> = Mutex::new(Cell::new(0));
#[ram]
static RECEIVING_STATUS: Mutex<Cell<bool>> = Mutex::new(Cell::new(false));
#[ram]
static HERALD_SEEN: Mutex<Cell<bool>> = Mutex::new(Cell::new(false));
#[ram]
static HERALD_LOCKED: Mutex<Cell<bool>> = Mutex::new(Cell::new(false));
#[ram]
static HERALD_TIME: Mutex<Cell<Instant>> = Mutex::new(Cell::new(time::Instant::from_ticks(0)));
#[ram]
static OUTCOME0_SEEN: Mutex<Cell<bool>> = Mutex::new(Cell::new(false));
#[ram]
static OUTCOME1_SEEN: Mutex<Cell<bool>> = Mutex::new(Cell::new(false));

// Starts a new bit reception cycle.
//
// A cycle is the period during which the TEE expects to receive a single bit of data from the generator,
// although in reality the process is noisy and the bit may not be received correctly.
#[ram]
fn start_cycle(cs: CriticalSection<'_>) {
    debug!("[ start_cycle ] Starting cycle.");
    HERALD_SEEN.borrow(cs).set(false);
    HERALD_LOCKED.borrow(cs).set(false);
    OUTCOME0_SEEN.borrow(cs).set(false);
    OUTCOME1_SEEN.borrow(cs).set(false);
    RECEIVING_STATUS.borrow(cs).set(true);
    debug!("[ start_cycle ] Cycle started.");
}

// Stops the current bit reception cycle.
//
// A cycle is the period during which the TEE expects to receive a single bit of data from the generator,
// although in reality the process is noisy and the bit may not be received correctly.
//
#[ram]
fn stop_cycle(cs: CriticalSection<'_>) {
    debug!("[ stop_cycle ] Stopping cycle.");
    RECEIVING_STATUS.borrow(cs).set(false);
    let cycle = CYCLE.borrow(cs);
    cycle.set(cycle.get() + 1);
    debug!("[ stop_cycle ] Cycle stopped.");
}

// Records that a herald photon has been observed in this bit reception cycle.
//
// Observation of a herald photon pre-empts the potential observation of a data photon, but it is not
// necessarily the case that the first herald photon observed is one which will be followed by a data photon.
// As a consequence, the time of herald photon observation is updated at each observation, until the first
// data photon is received (at which point the herald photon time is locked).
#[ram] //Placed in RAM for faster execution
fn see_herald(cs: CriticalSection<'_>) {
        if !RECEIVING_STATUS.borrow(cs).get() || HERALD_LOCKED.borrow(cs).get()
        {
            return
        } else {
            HERALD_TIME.borrow(cs).set(time::now());
            HERALD_SEEN.borrow(cs).set(true);
        }
}

// Records that a data photon has been measured with outcome 0 in this bit reception cycle.
// 
// Measurement of a data photon is only recorded if it happens after observation of a herald photon,
// within a pre-defined time window based on the time delays expected from the quantum HW setup.
#[ram] //Placed in RAM for faster execution
fn see_outcome0(cs: CriticalSection<'_>) {
    if !(RECEIVING_STATUS.borrow(cs).get() && HERALD_SEEN.borrow(cs).get())
        {
            return
        } else {
            let delay: Duration = time::now() - HERALD_TIME.borrow(cs).get();
            if delay.ticks() >= MIN_OUTCOME_DELAY_US && delay.ticks() <= MAX_OUTCOME_DELAY_US {
                HERALD_LOCKED.borrow(cs).set(true);
                OUTCOME0_SEEN.borrow(cs).set(true);
            }
        }
}

// Records that a data photon has been measured with outcome 0 in this bit reception cycle.
// 
// Measurement of a data photon is only recorded if it happens after observation of a herald photon,
// within a pre-defined time window based on the time delays expected from the quantum HW setup.
#[ram] //Placed in RAM for faster execution
fn see_outcome1(cs: CriticalSection<'_>) {
    //if (!CYCLE.borrow())
        if RECEIVING_STATUS.borrow(cs).get() && HERALD_SEEN.borrow(cs).get() {
            return
        } else {
            let delay: Duration = time::now() - HERALD_TIME.borrow(cs).get();
            if delay.ticks() >= MIN_OUTCOME_DELAY_US && delay.ticks() <= MAX_OUTCOME_DELAY_US {
                HERALD_LOCKED.borrow(cs).set(true);
                OUTCOME1_SEEN.borrow(cs).set(true);
            }
        }
}

// Sets the pin selecting the choice of measurement high or low.
fn set_basis(cs: CriticalSection<'_>, basis_select_pin: &mut Output<'_>, pin: bool) {
    if !RECEIVING_STATUS.borrow(cs).get() {
        if pin {
            basis_select_pin.set_high();
        } else {
            basis_select_pin.set_low();
        }
    }
}

#[main] //Placed in RAM for faster execution
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

    ///////////////
    // I/O STUFF //
    ///////////////
    info!("Initializing pins.");    
    let mut io = Io::new(peripherals.IO_MUX);
    io.set_interrupt_handler(handler);

    let mut running_pin = Output::new(peripherals.GPIO20, Level::Low);
    let mut basis_select_pin = Output::new(peripherals.GPIO14, Level::Low);
    let receiving_pin = Input::new(peripherals.GPIO21, Pull::Up);
    let herald_pin = Input::new(peripherals.GPIO22, Pull::Up);
    let outcome0_pin = Input::new(peripherals.GPIO16, Pull::Up);
    let outcome1_pin = Input::new(peripherals.GPIO17, Pull::Up);

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
    wdt.set_timeout(MwdtStage::Stage0, Duration::secs(timeout_seconds)); // Watchdog triggers after n secs of inactivity
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
    info!("Consol buffer initialized.");

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
    let mut state_machine = MeasurementDialog;
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
                let buffer = store_serial_buffer(&mut buffer, &mut usb_serial);
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
                        aes256(&mut decode(&buffer).unwrap(), Mode::Decryption256, &mut aes, &mut sha);
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
                    match ConjugateCodingPreparePlaintext::deserialize(&decrypted_buffer) {
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
                    program_hash = hash256(buffer, &mut sha)[0..preparation.total_size].to_vec();
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
                let mut outcomes: Vec<u8> = vec![0,0];
                let mut success: Vec<u8> = vec![0,0];
                let mut outcomes_byte: u8 = 0;
                let mut success_byte: u8 = 0;

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
                    cycle.set(0);
                    receiving_pin.listen(Event::AnyEdge);
                    herald_pin.listen(Event::RisingEdge);
                    outcome0_pin.listen(Event::RisingEdge);
                    outcome1_pin.listen(Event::RisingEdge);
                    set_basis(initialize_sec, &mut basis_select_pin, read_nth_bit(program_hash[0], 0));
                    running_pin.set_high();
                });
                while critical_section::with(|initialize_sec| { CYCLE.borrow(initialize_sec).get() < preparation.total_size }) {
                    critical_section::with(|while_sec| {
                        // If we're not receiving, a whole cycle has completed and
                        // We can store values.
                        if !RECEIVING_STATUS.borrow(while_sec).get() {
                            trace!(
                                "[ {:?} ] Cycle concluded, assigning inputs.",
                                MeasurementInput
                            );
                            let cycle = CYCLE.borrow(while_sec).get();
                            trace!(
                                "[ {:?} ] Cycle: {:?}.",
                                MeasurementInput,
                                cycle
                            );
                            if cycle % 8 == 0 {
                                trace!(
                                    "[ {:?} ] New byte started.",
                                    MeasurementInput
                                );
                                outcomes_byte = 0;
                                success_byte = 0;
                            } else {
                                trace!(
                                    "[ {:?} ] Modifying byte in the outcome/success vector.",
                                    MeasurementInput
                                );
                                outcomes_byte = outcomes.pop().unwrap();
                                success_byte = success.pop().unwrap();
                            }
                            let herald_seen = HERALD_SEEN.borrow(while_sec);
                            let outcome0_seen = OUTCOME0_SEEN.borrow(while_sec);
                            let outcome1_seen = OUTCOME1_SEEN.borrow(while_sec);
                            if herald_seen.get() && (outcome0_seen.get() ^ outcome1_seen.get()) {
                                write_nth_bit(outcomes_byte, cycle % 8 , outcome1_seen.get());
                                write_nth_bit(success_byte, cycle % 8 , true);
                            } else {
                                write_nth_bit(success_byte, cycle % 8, false);
                            }
                            trace!(
                                "[ {:?} ] outcomes: {:?}.",
                                MeasurementInput,
                                outcomes
                            );
                            trace!(
                                "[ {:?} ] success: {:?}.",
                                MeasurementInput,
                                success
                            );
                            // Here we change basis every couple of qubits measured.
                            if cycle % 2 == 0 {
                                trace!(
                                    "[ {:?} ] Chainging basis.",
                                    MeasurementInput
                                );
                                trace!(
                                    "[ {:?} ] Basis: {:?}.",
                                    MeasurementInput,
                                    read_nth_bit(program_hash[cycle/16], cycle/2 % 8)
                                );
                                set_basis(while_sec, &mut basis_select_pin, read_nth_bit(program_hash[cycle/16], cycle/2 % 8));
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
                    "[ {:?} ] outcomes: {:?}.",
                    MeasurementInput,
                    outcomes
                );
                debug!(
                    "[ {:?} ] success: {:?}.",
                    MeasurementInput,
                    success
                );
                match ConjugateCodingMeasure::from_plaintext(
                    &preparation,
                    program_hash.clone(),
                    outcomes.clone(),
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
                match ConjugateCodingResult::new(&preparation, &measurement, 0) {
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
