#![no_std]
#![no_main]

extern crate alloc;
use core::ptr::addr_of_mut;

use esp_backtrace as _;
use esp_println as _;
use esp_alloc as _;

use esp_hal::{
    clock::CpuClock,
    aes::Aes,
    aes::Mode,
    main,
};
use esp_println::println;

use serde::{Serialize, Deserialize};
use conjugate_coding;

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

#[main]
fn main() -> ! {
    init_heap();

    let peripherals = esp_hal::init({
        let mut config = esp_hal::Config::default();
        // Configure the CPU to run at the maximum frequency.
        config.cpu_clock = CpuClock::max();
        config
    });

    let mut aes = Aes::new(peripherals.AES);

    // Hardcoded keys are obviously insecure. Consider this just an example!
    let keytext = "SUp4SeCp@sSw0rd".as_bytes(); 
    let plaintext = "message".as_bytes();
    
    // create an array with aes128 key size
    let mut keybuf = [0_u8; 32];
    keybuf[..keytext.len()].copy_from_slice(keytext);
    
    // create an array with aes block size
    let mut block_buf = [0_u8; 16];
    block_buf[..plaintext.len()].copy_from_slice(plaintext);

    let mut block = block_buf.clone();
    aes.process(&mut block, Mode::Encryption256, keybuf);
    let hw_encrypted = block.clone();

    aes.process(&mut block, Mode::Decryption256, keybuf);
    let hw_decrypted = block;

    println!("Hello, world!");

    defmt::trace!("trace");
    defmt::debug!("debug");
    defmt::info!("info");
    defmt::warn!("warn");
    defmt::error!("error");
    
    loop {};
}
