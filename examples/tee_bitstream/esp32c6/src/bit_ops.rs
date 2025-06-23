/////////////////////
// BYTE OPERATIONS //
/////////////////////

use defmt::trace;

// Checks if the n-th bit of a byte is 1.
pub fn read_nth_bit(byte: u8, bit: usize) -> bool {
    let mask: [u8; 8] = [128, 64, 32, 16, 8, 4, 2, 1];
    byte & mask[bit] != 0
}

// Sets nth bit of a byte.
pub fn write_nth_bit(byte: u8, bit: usize, value: bool) -> u8 {
    let mask: u8 = 1 << (7 - bit);
    trace!("byte: 0b{:08b}", byte);
    trace!("mask: 0b{:08b}", mask);
    trace!("value: 0b{:08b}", value);
    let result: u8;
    if value {
        result = byte | mask;
        trace!("New byte: 0b{:08b}", result);
    } else {
        result = byte & !mask;
        trace!("New byte: 0b{:08b}", result);
    }
    return result;
}