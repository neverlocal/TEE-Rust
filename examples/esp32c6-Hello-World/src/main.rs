#![no_std]
#![no_main]

extern crate alloc; // no_std requires a custom allocator
use core::ptr::addr_of_mut; // Needed to initialize heap

// Logging, printing etc.
use esp_backtrace as _;
use esp_println as _;
use defmt:: {trace, info, debug, warn, error, println};

use esp_hal::{
    clock::CpuClock,                // Set the CPU clock
    aes::Aes,                       // AES ecnryption-decryption scheme
    aes::Mode,                      // AES mode (128, 256, etc)
    delay::Delay,                   // Needed to reset the watchdog and for setting delays
    timer::timg::TimerGroup,        // Needed to reset the watchdog
    timer::timg::MwdtStage,         // Needed to reset the watchdog
    time::Duration,                 // Needed to reset the watchdog and for setting delays
    usb_serial_jtag::UsbSerialJtag, // Needed to communicate over USB
    main
};

use embedded_io::Write;

use serde::{Serialize, Deserialize}; // We do like our JSON very much

use conjugate_coding; // Finally the only meaningful thing in a sea of boilerplate


fn init_heap() { // Function to initialize the heap memory
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

    info!("This is TEE-Rust.");

////////////////
// HEAP STUFF //
////////////////
    // Here we initialize the heap and the peripherals
    init_heap();
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);
    // Alternative config, more verbose but better to customize several options.
    // let peripherals = esp_hal::init({
    //     let mut config = esp_hal::Config::default();
    //     // Configure the CPU to run at the maximum frequency.
    //     config.cpu_clock = CpuClock::max();
    //     config
    // });
    info!("Heap initialized.");
    
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

//////////////
// Watchdog //
//////////////
    // Esp32 chips have a nasty watchdog
    // that decides to kill your program
    // if the same task runs for too long.
    // Here we create a watchdog and constanly
    // feed it to avoid this.
    let timg0 = TimerGroup::new(peripherals.TIMG0); // Create a new timer
    let mut wdt = timg0.wdt;                        // Use it to create a new watchdog
    
    wdt.set_timeout(MwdtStage::Stage0, Duration::secs(600)); // Watchdog triggers after n secs of inactivity
    wdt.enable();                                            // We enable the damn thing

//////////////////
// Serial Comms //
//////////////////
    let mut usb_serial = UsbSerialJtag::new(peripherals.USB_DEVICE);
    //let (mut rx, mut tx) = usb_serial.split();

    ///////////////
// MAIN LOOP //
///////////////

    let delay = Delay::new(); // Initialize delay
    loop {
        trace!("trace");
        debug!("debug");
        info!("info");
        warn!("warn");
        error!("error!");
        println!("Hello world.");

        writeln!(
            usb_serial,
            "Please don't let Jesus cry"
        ).ok();
        delay.delay_millis(1000);
        wdt.feed();
    }
}
