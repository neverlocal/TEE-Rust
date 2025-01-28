#![no_std]
#![no_main]

extern crate alloc;
use core::ptr::addr_of_mut;

use embassy_executor::Spawner;
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, signal::Signal};

use esp_backtrace as _;

use esp_hal::{
    clock::CpuClock,
    aes::Aes, // AES ecnryption-decryption scheme
    aes::Mode, // AES mode (128, 256, etc)
    timer::timg::TimerGroup, // Hardware timers
    uart::{AtCmdConfig, Uart, UartRx, UartTx}, // Serial comms
    Async, // Async behavior
};
use static_cell::StaticCell; // In no_std async context we need this to define mutexes etc.

use defmt::println; // Logging,printing etc
use serde::{Serialize, Deserialize}; // We do like our JSON very much

use conjugate_coding; // Finally the only meaningful thing in a sea of boilerplate


const READ_BUF_SIZE: usize = 64; // Buffer size for UART read/write
const AT_CMD: u8 = 0x04; // Defines the end-of-transmission (EOT) character (CTRL-D) used to signal the end of input.
const MAX_BUFFER_SIZE: usize = 10 * READ_BUF_SIZE + 16;

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


#[esp_hal_embassy::main]
async fn main(spawner: Spawner) { // Main function
    defmt::info!("This is TEE-Rust.");

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
    defmt::debug!("Heap initialized.");
    
    // Here we initialize a timer, which is needed for embassy to work asynchronously.
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_hal_embassy::init(timg0.timer0);
    defmt::debug!("Embassy initialized.");

    // UARD init
    let (tx_pin, rx_pin) = (peripherals.GPIO21, peripherals.GPIO20); // Default pins for Uart communication
    let uart_config = esp_hal::uart::Config::default().with_rx_fifo_full_threshold(READ_BUF_SIZE as u16);
    let mut uart0 = Uart::new(peripherals.UART0, uart_config)
        .unwrap()
        .with_tx(tx_pin)
        .with_rx(rx_pin)
        .into_async();
    uart0.set_at_cmd(AtCmdConfig::default().with_cmd_char(AT_CMD));
    let (rx, tx) = uart0.split(); // We split rx and tx components to work asynchronously

    // Spawn read and write processes
    static SIGNAL: StaticCell<Signal<NoopRawMutex, (usize, usize, [u8; MAX_BUFFER_SIZE])>> = StaticCell::new();
    let signal: &Signal<NoopRawMutex, (usize, usize, [u8; MAX_BUFFER_SIZE])> = &*SIGNAL.init(Signal::new()); // The mutex
   
    spawner.spawn(writer(tx, &signal)).ok(); // The write process
    spawner.spawn(reader(rx, &signal)).ok(); // The read process

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


    defmt::trace!("trace");
    defmt::debug!("debug");
    defmt::info!("info");
    defmt::warn!("warn");
    defmt::error!("error");

}

#[embassy_executor::task]
async fn writer(mut tx: UartTx<'static, Async>,
                signal: &'static Signal<NoopRawMutex, (usize, usize, [u8; MAX_BUFFER_SIZE])>,
) {
    use core::fmt::Write;
    embedded_io_async::Write::write(
        &mut tx,
        b"Protocol is ready. I'm waiting for encrypted JSON input from preparing party. Enter something ended with EOT (CTRL-D).\r\n",
    )
    .await
    .unwrap();
    embedded_io_async::Write::flush(&mut tx).await.unwrap();
    loop {
        let bytes_read = signal.wait().await;
        signal.reset();
        write!(&mut tx, "\r\n-- received {} bytes --\r\n", bytes_read.0).unwrap();
        embedded_io_async::Write::flush(&mut tx).await.unwrap();
    }
}

#[embassy_executor::task]
async fn reader(
    mut rx: UartRx<'static, Async>,
    signal: &'static Signal<NoopRawMutex, (usize, usize, [u8; MAX_BUFFER_SIZE])>,
) {
    let mut rbuf: [u8; MAX_BUFFER_SIZE] = [0u8; MAX_BUFFER_SIZE];

    let mut offset = 0;
    loop {
        let r = embedded_io_async::Read::read(&mut rx, &mut rbuf[offset..]).await;
        match r {
            Ok(len) => {
                offset += len;
                esp_println::println!("Read: {len}, data: {:?}", &rbuf[..offset]);
                offset = 0;
                signal.signal((len,0,rbuf));
            }
            Err(e) => esp_println::println!("RX Error: {:?}", e),
        }
    }
}
