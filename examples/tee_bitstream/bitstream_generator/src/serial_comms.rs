//////////////////
// SERIAL COMMS //
//////////////////
use defmt::{println, trace};

extern crate alloc; // no_std requires a custom allocator
use alloc::vec::Vec; // Needed for buffer manipulation

use esp_hal::usb_serial_jtag::UsbSerialJtag;

// Reads from serial and returns a buffer object
pub fn store_serial_buffer<'a>(
    buffer: &'a mut Vec<u8>,
    usb_serial: &mut UsbSerialJtag<'_, esp_hal::Blocking>,
) -> &'a mut Vec<u8> {
    while let Result::Ok(c) = usb_serial.read_byte() {
        //trace!("Old Buffer: {=[u8]:x}", buffer);
        match c {
            0x0..0x4 | 0x05..0x08 | 0x9..0x0D | 0x0F..=0x1F | 0x80..=0xff => trace!(
                "[ store_serial_buffer ] Special char {:x} detected. Doing nothing.",
                c
            ),
            0x4 => {
                trace!("[ store_serial_buffer ] Special char {:x} (EOT) detected. Pushing into buffer and returning.", c);
                buffer.push(c); // Push char into buffer
            }
            0x8 => {
                trace!(
                    "[ store_serial_buffer ] Special char {:x} (Backspace) detected.",
                    c
                );
                match buffer.pop() {
                    // Strip last char out of buffer
                    Some(_x) => {
                        trace!("[ store_serial_buffer ] Buffer was not empyt. Last char in buffer cleared.");
                        let _ = usb_serial.write_byte_nb(c); // Display: Cursor 1 to the left
                        let _ = usb_serial.write_byte_nb(0x20); //Display: replace last char with space
                        let _ = usb_serial.write_byte_nb(c); // Display: Cursor 1 to the left again
                        usb_serial.flush_tx().ok();
                    }
                    None => trace!("[ store_serial_buffer ] Buffer was already empty!"),
                }
            }
            0x0D => {
                println!("");
                trace!(
                    "[ store_serial_buffer ] Special char {:x} (Newline) detected.",
                    c
                )
            }
            _ => {
                trace!(
                    "[ store_serial_buffer ] Char {:x} detected. Adding to buffer.",
                    c
                );
                let _ = usb_serial.write_byte_nb(c); // Display: Write char
                usb_serial.flush_tx().ok();
                buffer.push(c); // Push char into buffer
            }
        }
        trace!("[ store_serial_buffer ] New Buffer: {=[u8]:x}", buffer);
    }
    return buffer;
}
