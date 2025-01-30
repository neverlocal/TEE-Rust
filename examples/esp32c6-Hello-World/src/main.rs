#![no_std]
#![no_main]

extern crate alloc; // no_std requires a custom allocator
//use alloc::vec; // Needed for buffer manipulation
use alloc::vec::Vec; // Needed for buffer manipulation

use alloc::string::String;
use serde::de::Error;
use hex;

use core::ptr::addr_of_mut; // Needed to initialize heap

// Logging, printing etc.
use defmt::{trace, debug, error, info, println, Format};
use esp_backtrace as _;
use esp_println as _;

use esp_hal::{
    // aes::Aes,        // AES ecnryption-decryption scheme
    // aes::Mode,       // AES mode (128, 256, etc)
    clock::CpuClock, // Set the CPU clock
    time::Duration,          // Needed to reset the watchdog and for setting delays
    timer::timg::MwdtStage,  // Needed to reset the watchdog
    timer::timg::TimerGroup, // Needed to reset the watchdog
    usb_serial_jtag::UsbSerialJtag, // Needed to communicate over USB
    main,
};

// Rewrite memory locations with 0s after drop, useful for security reasons
use zeroize::{Zeroize, ZeroizeOnDrop};

use core::result::Result;
use serde::{ Deserialize, Deserializer}; // We do like our JSON very much

// Finally the only meaningful thing in a sea of boilerplate
use conjugate_coding; 
use conjugate_coding::conjugate_coding::{ConjugateCodingMeasure, ConjugateCodingPrepare};

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
    let timeout_seconds = 600;
    wdt.set_timeout(MwdtStage::Stage0, Duration::secs(timeout_seconds)); // Watchdog triggers after n secs of inactivity
        info!("Timeout set to {} seconds.",timeout_seconds);
    wdt.enable(); // We enable the damn thing
        info!("Watchdog enabled.");
    
//////////////////
// Serial Comms //
//////////////////
    let mut usb_serial = UsbSerialJtag::new(peripherals.USB_DEVICE);
        info!("JTAG interface initialized.");
    let mut buffer: Vec<u8> = alloc::vec![0;0];
        info!("Consol buffer initialized.");

///////////////////
// State Machine //
///////////////////
    enum StateMachine {
        PreparationDialog,        // Greetings etc.
        PreparationInput,   // 
        MeasurementDialog,       //
        MeasurementInput,   //
        ComputeSecret,      //
        RunProgram,         //
        FinalDialog,        //
    }
    let mut state_machine: StateMachine = StateMachine::PreparationDialog;
        info!("Protocol state machine initialized.");


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
        secret_size:   usize,
        security_size: usize,
        orderings:     Vec<u8>,
        bitmask:       Vec<u8>,
        security0:     Vec<u8>,
        security1:     Vec<u8>,
    }

    impl ConjugateCodingPreparePlaintext {
        fn deserialize(json_vec: &[u8]) -> Result<Self, serde_json::Error> {
            #[derive(Deserialize)]
            struct HexPlainData {
                secret_size: usize,
                security_size: usize,
                #[serde(deserialize_with = "deserialize_vec_from_hex_string")]
                orderings: Vec<u8>,
                #[serde(deserialize_with = "deserialize_vec_from_hex_string")]
                bitmask: Vec<u8>,
                #[serde(deserialize_with = "deserialize_vec_from_hex_string")]
                security0: Vec<u8>,
                #[serde(deserialize_with = "deserialize_vec_from_hex_string")]
                security1: Vec<u8>,
            }
    
            let hex_data: HexPlainData = serde_json::from_slice(json_vec)?;
    
            Ok(ConjugateCodingPreparePlaintext {
                secret_size: hex_data.secret_size,
                security_size: hex_data.security_size,
                orderings: hex_data.orderings,
                bitmask: hex_data.bitmask,
                security0: hex_data.security0,
                security1: hex_data.security1,
            })
        }
    }

    #[derive(Zeroize, ZeroizeOnDrop, Deserialize, Format)]
    pub struct ConjugateCodingMeasurePlaintext {
        total_size:    usize,
        outcomes:  Vec<u8>,
        choices:       Vec<u8>,
    }

    impl ConjugateCodingMeasurePlaintext {
        fn deserialize(json_vec: &[u8]) -> Result<Self, serde_json::Error> {
            #[derive(Deserialize)]
            struct HexPlainData {
                total_size: usize,
                #[serde(deserialize_with = "deserialize_vec_from_hex_string")]
                outcomes: Vec<u8>,
                #[serde(deserialize_with = "deserialize_vec_from_hex_string")]
                choices: Vec<u8>,
            }
    
            let hex_data: HexPlainData = serde_json::from_slice(json_vec)?;
    
            Ok(ConjugateCodingMeasurePlaintext {
                total_size: hex_data.total_size,
                outcomes: hex_data.outcomes,
                choices: hex_data.choices,
            })
        }
    }

    let mut preparation = ConjugateCodingPrepare::new_from_zero();
    let mut measurement = ConjugateCodingMeasure::new_from_zero();

///////////////
// MAIN LOOP //
///////////////
    info!("Entering main loop...");
    loop {
        match state_machine {
            StateMachine::PreparationDialog => {
                debug!("[ PreparationDialog ] Protocol is in state 'PreparationDialog'.");
                println!("This is TEE-Rust.");
                println!("[ PREPARATION ] The protocol is in preparation phase.");
                println!("[ PREPARATION ] Please provide the preparation information in JSON format.");
                println!("[ PREPARATION ] Backspace works normally.");
                println!("[ PREPARATION ] ENTER is not send. You can press ENTER to go to a new line.");
                println!("[ PREPARATION ] Press CTRL+D (UTF8 0004, EOT) to submit information.");
                println!("");
                wdt.feed();
                    debug!("[ PreparationDialog ] Watchdog fed.");
                state_machine = StateMachine::PreparationInput;
                    debug!("[ PreparationDialog ] Protocol transitioned to state 'PreparationInput'.");
            },
            StateMachine::PreparationInput => {
                let buffer = store_serial_buffer(&mut buffer, &mut usb_serial);
                if (buffer.len() > 0) && buffer[buffer.len()-1] == 04 {
                    println!("");
                    println!("[ PREPARATION ] Information submitted. Validating...");
                        debug!("[ PreparationInput ] Buffer: {=[u8]:x}", buffer);
                    buffer.pop();
                        debug!("[ PreparationInput ] Got rid of EOT char. New buffer: {=[u8]:x}", buffer);
                    match ConjugateCodingPreparePlaintext::deserialize(&buffer) {
                        Err(_) => {
                            error!("[ PREPARATION ] Protocol wasn't able to parse the string. Restarting protocol...");
                            buffer.zeroize();
                                debug!("[ PreparationInput ] Buffer has been zeroized: New buffer: {=[u8]:x}", buffer);
                            state_machine = StateMachine::PreparationDialog;
                                debug!("[ PreparationInput ] Protocol transitioned to state 'PreparationDialog'.");                            
                        },
                        Ok(deserialized_buffer) => {
                            println!("[ PREPARATION ] JSON input is of the right format. Validating information...");
                                debug!("[ PreparationInput ] deserialized_buffer: {:?}", deserialized_buffer);
                            buffer.zeroize();
                                debug!("[ PreparationInput ] Buffer has been zeroized: New buffer: {=[u8]:x}", buffer);
                            match ConjugateCodingPrepare::new_plaintext(
                                deserialized_buffer.secret_size,
                                deserialized_buffer.security_size,
                                deserialized_buffer.orderings.clone(),
                                deserialized_buffer.bitmask.clone(),
                                deserialized_buffer.security0.clone(),
                                deserialized_buffer.security1.clone()
                            ) {
                                Ok(result) => {
                                    println!("[ PREPARATION ] Information validated.");
                                    preparation = result;
                                        debug!("[ PreparationInput ] Preparation struct assigned.");
                                    state_machine = StateMachine::MeasurementDialog;
                                        debug!("[ PreparationInput ] Protocol transitioning to state 'PreparationAssign'.");
                                },
                                Err(e) => {
                                    error!("[ PREPARATION ] Information validation failed with error:\n      \
                                            {:?}. \
                                            Restarting protocol...", e);
                                    state_machine = StateMachine::PreparationDialog;
                                        debug!("[ PreparationInput ] Protocol transitioned to state 'PreparationDialog'."); 
                                }
                            }
                        }
                    };
                }
                wdt.feed();
                    debug!("[ PreparationInput ] Watchdog fed.");
            }
            StateMachine::MeasurementDialog => {
                debug!("[ MeasurementDialog ] Protocol is in state 'MeasurementDialog'.");
                println!("This is TEE-Rust.");
                println!("[ MEASUREMENT ] The protocol is in measurement phase.");
                println!("[ MEASUREMENT ] Please provide the measurement information in JSON format.");
                println!("[ MEASUREMENT ] Backspace works normally.");
                println!("[ MEASUREMENT ] ENTER is not send. You can press ENTER to go to a new line.");
                println!("[ MEASUREMENT ] Press CTRL+D (UTF8 0004, EOT) to submit information.");
                println!("");
                wdt.feed();
                    debug!("[ MeasurementDialog ] Watchdog fed.");
                state_machine = StateMachine::MeasurementInput;
                    debug!("[ MeasurementDialog ] Protocol transitioned to state 'MeasurementInput'.");
            },

            StateMachine::MeasurementInput => {
                let buffer = store_serial_buffer(&mut buffer, &mut usb_serial);
                if (buffer.len() > 0) && buffer[buffer.len()-1] == 04 {
                    println!("");
                    println!("[ MEASUREMENT ] Information submitted. Validating...");
                        debug!("[ MeasurementInput ] Buffer: {=[u8]:x}", buffer);
                    buffer.pop();
                        debug!("[ MeasurementInput ] Got rid of EOT char. New buffer: {=[u8]:x}", buffer);
                    match ConjugateCodingMeasurePlaintext::deserialize(&buffer) {
                        Err(_) => {
                            error!("[ MEASUREMENT ] Protocol wasn't able to parse the string. Please retry.");
                            buffer.zeroize();
                                debug!("[ MeasurementInput ] Buffer has been zeroized: New buffer: {=[u8]:x}", buffer);
                            state_machine = StateMachine::MeasurementDialog;
                                debug!("[ MeasurementInput ] Protocol transitioned to state 'MeasurementDialog'.");                            
                        },
                        Ok(deserialized_buffer) => {
                            println!("[ MEASUREMENT ] JSON input is of the right format. Validating information...");
                                debug!("[ MeasurementInput ] deserialized_buffer: {:?}", deserialized_buffer);
                            buffer.zeroize();
                                debug!("[ MeasurementInput ] Buffer has been zeroized: New buffer: {=[u8]:x}", buffer);
                            match ConjugateCodingMeasure::new_plaintext(
                                &preparation,
                                deserialized_buffer.outcomes.clone(),
                                deserialized_buffer.choices.clone(),
                            ) {
                                Ok(result) => {
                                    println!("[ MEASUREMENT ] Information validated.");
                                    measurement = result;
                                        debug!("[ MeasurementInput ] Measurement struct assigned.");
                                    state_machine = StateMachine::ComputeSecret;
                                        debug!("[ MeasurementInput ] Protocol transitioning to state 'ComputeSecret'.");
                                },
                                Err(e) => {
                                    error!("[ MEASUREMENT ] Information validation failed with error:\n      \
                                            {:?}. \
                                            Please retry.", e);
                                    state_machine = StateMachine::MeasurementDialog;
                                        debug!("[ MeasurementInput ] Protocol transitioned to state 'MeasurementDialog'."); 
                                }
                            }
                        }
                    };
                }
                wdt.feed();
                    debug!("[ MeasurementInput ] Watchdog fed.");
            }

            _ => wdt.feed()
        }        
    }
}



// Reads from serial and returns a buffer object
fn store_serial_buffer<'a>(buffer: &'a mut Vec<u8>, usb_serial: &mut UsbSerialJtag<'_, esp_hal::Blocking>) -> &'a mut Vec<u8> {
    while let Result::Ok(c) = usb_serial.read_byte() {
            //trace!("Old Buffer: {=[u8]:x}", buffer);
        match c {
            0x0..0x4|0x05..0x08|0x9..0x0D|0x0F..=0x1F|0x80..=0xff => trace!("store_serial_buffer: Special char {:x} detected. Doing nothing.", c),
            0x4 => {
                trace!("store_serial_buffer: Special char {:x} (EOT) detected. Pushing into buffer and returning.", c);
                buffer.push(c); // Push char into buffer
            }
            0x8 => {
                trace!("store_serial_buffer: Special char {:x} (Backspace) detected.", c);
                match buffer.pop() { // Strip last char out of buffer
                    Some(_x) => {
                        trace!("store_serial_buffer: Buffer was not empyt. Last char in buffer cleared.");
                        let _ = usb_serial.write_byte_nb(c);    // Display: Cursor 1 to the left
                        let _ = usb_serial.write_byte_nb(0x20); //Display: replace last char with space
                        let _ = usb_serial.write_byte_nb(c);    // Display: Cursor 1 to the left again
                        usb_serial.flush_tx().ok();
                    },
                    None => trace!("store_serial_buffer: Buffer was already empty!")
                } 
            }
            0x0D => { println!(""); trace!("store_serial_buffer: Special char {:x} (Newline) detected.", c) }
            _ => {
                trace!("store_serial_buffer: Char {:x} detected. Adding to buffer.", c);
                let _ = usb_serial.write_byte_nb(c); // Display: Write char
                usb_serial.flush_tx().ok();
                buffer.push(c); // Push char into buffer
            }
        }
        trace!("store_serial_buffer: New Buffer: {=[u8]:x}", buffer);
    }
    return buffer;
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