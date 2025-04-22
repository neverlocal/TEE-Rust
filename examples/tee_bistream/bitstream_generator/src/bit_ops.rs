/////////////////////
// BYTE OPERATIONS //
/////////////////////
// Checks if the n-th bit of a byte is 1.
pub fn read_nth_bit(byte: u8, bit: usize) -> bool {
    let mask: [u8; 8] = [128, 64, 32, 16, 8, 4, 2, 1];
    byte & mask[bit] != 0
}
