#![no_std]
#![no_main]

use esp_backtrace as _;
use esp_hal::{
    delay::Delay,
    gpio::{Level, Output},
    main,
};
use esp_println::println;

mod conjugate_coding;

#[main]
fn main() -> ! {
    println!("Hello, world!");
}
