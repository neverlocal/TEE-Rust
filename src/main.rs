#![no_std]
#![no_main]

use esp_backtrace as _;
use esp_alloc as _;

use esp_hal::{
    main,
};
use esp_println::println;
use conjugate_coding;

#[main]
fn main() -> ! {
    println!("Hello, world!");
    loop {};
}
