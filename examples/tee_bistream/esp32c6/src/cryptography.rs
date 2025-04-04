//////////////////
// CRYPTOGRAPHY //
//////////////////
use defmt::trace;

extern crate alloc; // no_std requires a custom allocator
use alloc::vec::Vec; // Needed for buffer manipulation

use esp_hal::{
    aes::{Aes, Mode},
    sha::{Sha, Sha256},
};

use nb::block;

pub fn hash256(buffer: &[u8], sha: &mut Sha<'_>) -> [u8; 32] {
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
pub fn aes256(buffer: &mut Vec<u8>, mode: Mode, aes: &mut Aes<'_>, sha: &mut Sha<'_>, key: &[u8]) -> Vec<u8> {
    let keybuf = hash256(key, sha);
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
