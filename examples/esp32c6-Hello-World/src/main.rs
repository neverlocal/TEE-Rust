#![no_std]
#![no_main]

extern crate alloc; // no_std requires a custom allocator
use core::ptr::addr_of_mut; // Needed to initialize heap

// Logging, printing etc.
use defmt::{debug, error, info, println, trace, warn};
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

use core::result::Result;
use serde_json::Value;
// use serde::{Deserialize, Serialize}; // We do like our JSON very much

// use conjugate_coding; // Finally the only meaningful thing in a sea of boilerplate

pub use alloc::vec;
pub use alloc::vec::Vec;

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
    let mut buffer: Vec<u8> = vec![0;0];
        info!("Consol buffer initialized.");
///////////////////
// State Machine //
///////////////////
enum StateMachine {
    FirstDialog,        // Greetings etc.
    PreparationInput,   // 
    PreparationAssign,  //
    SecondPrompt,       //
    MeasurementInput,   //
    MeasurementAssign,  //
    ComputeSecret,      //
    RunProgram,         //
    FinalDialog,        //
}
let mut state_machine: StateMachine = StateMachine::FirstDialog;
    info!("Protocol state machine initialized.");

///////////////
// MAIN LOOP //
///////////////
    info!("Entering main loop...");
    loop {
        match state_machine {
            StateMachine::FirstDialog => {
                info!("[ FistDialog ] Protocol is in state 'FistDialog'.");
                println!("This is TEE-Rust.");
                println!("[ PREPARATION ] The protocol is in preparation phase.");
                println!("[ PREPARATION ] Please provide the preparation information in JSON format.");
                println!("[ PREPARATION ] Backspace works normally.");
                println!("[ PREPARATION ] ENTER is not send. You can press ENTER to go to a new line.");
                println!("[ PREPARATION ] Press CTRL+D (UTF8 0004, EOT) to submit information.");
                state_machine = StateMachine::PreparationInput;
                    info!("[ FistDialog ] Protocol transitioning to state 'PreparationInput'.");
            },
            StateMachine::PreparationInput => {
                let buffer = store_serial_buffer(&mut buffer, &mut usb_serial);
                if (buffer.len() > 0) && buffer[buffer.len()-1] == 04 {
                        println!("");
                        info!("[ PreparationInput ] Information submitted. Buffer: {=[u8]:x}", buffer);
                    buffer.pop();
                        info!("[ PreparationInput ] Got rid of EOT char. New buffer: {=[u8]:x}", buffer);
                    let v: Value = serde_json::from_slice(&buffer).unwrap();
                        info!("[ PreparationInput ] Serde correctly parsed input.");
                    buffer.clear();
                        info!("[ PreparationInput ] Buffer has been cleared: New buffer: {=[u8]:x}", buffer);
                    state_machine = StateMachine::PreparationAssign;
                        info!("[ PreparationInput ] Protocol transitioning to state 'PreparationAssign'.");
                }
            }
            StateMachine::PreparationAssign => (),
            _ => ()
        }        
        wdt.feed();
    }
}




// Reads from serial and returns a buffer object
fn store_serial_buffer<'a>(buffer: &'a mut Vec<u8>, usb_serial: &mut UsbSerialJtag<'_, esp_hal::Blocking>) -> &'a mut Vec<u8> {
    while let Result::Ok(c) = usb_serial.read_byte() {
            //debug!("Old Buffer: {=[u8]:x}", buffer);
        match c {
            0x0..0x4|0x05..0x08|0x9..0x0D|0x0F..=0x1F|0x80..=0xff => debug!("store_serial_buffer: Special char {:x} detected. Doing nothing.", c),
            0x4 => {
                debug!("store_serial_buffer: Special char {:x} (EOT) detected. Pushing into buffer and returning.", c);
                buffer.push(c); // Push char into buffer
            }
            0x8 => {
                debug!("store_serial_buffer: Special char {:x} (Backspace) detected.", c);
                match buffer.pop() { // Strip last char out of buffer
                    Some(_x) => {
                        debug!("store_serial_buffer: Buffer was not empyt. Last char in buffer cleared.");
                        let _ = usb_serial.write_byte_nb(c);    // Display: Cursor 1 to the left
                        let _ = usb_serial.write_byte_nb(0x20); //Display: replace last char with space
                        let _ = usb_serial.write_byte_nb(c);    // Display: Cursor 1 to the left again
                        usb_serial.flush_tx().ok();
                    },
                    None => debug!("store_serial_buffer: Buffer was already empty!")
                } 
            }
            0x0D => { println!(""); debug!("store_serial_buffer: Special char {:x} (Newline) detected.", c) }
            _ => {
                debug!("store_serial_buffer: Char {:x} detected. Adding to buffer.", c);
                let _ = usb_serial.write_byte_nb(c); // Display: Write char
                usb_serial.flush_tx().ok();
                buffer.push(c); // Push char into buffer
            }
        }
        debug!("store_serial_buffer: New Buffer: {=[u8]:x}", buffer);
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