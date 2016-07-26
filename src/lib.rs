//! A Rust API for working with OSX's Mach-O object files.

#![deny(missing_docs)]

extern crate mach_o_sys;

use mach_o_sys::loader;
use std::marker::PhantomData;
use std::mem;

/// An error that occurred while parsing the mach-o file contents.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// The input is not long enough to contain valid contents.
    InputNotLongEnough,
    /// Found an unknown magic header value.
    UnknownMagicHeaderValue,
}

/// The byte order of the mach-o file.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Endian {
    /// Big endian byte order.
    Big,
    /// Little endian byte order.
    Little,
}

#[derive(Copy, Clone, Debug)]
enum RawHeader {
    MachHeader32(*const loader::mach_header),
    MachHeader64(*const loader::mach_header_64),
}

/// A mach-o file header.
#[derive(Copy, Clone, Debug)]
pub struct Header<'a> {
    endian: Endian,
    raw_header: RawHeader,
    phantom: PhantomData<&'a [u8]>,
}

impl<'a> Header<'a> {
    /// Parse the mach-o file header from the given input slice.
    pub fn new(input: &'a [u8]) -> Result<Header<'a>, Error> {
        if input.len() < mem::size_of::<loader::mach_header>() {
            return Err(Error::InputNotLongEnough);
        }

        let mut magic: [u8; 4] = [0, 0, 0, 0];
        magic.copy_from_slice(&input[..4]);
        let magic = unsafe { mem::transmute(magic) };

        match magic {
            // 32 bit, little endian.
            loader::MH_MAGIC => {
                Ok(Header {
                    endian: Endian::Little,
                    raw_header: RawHeader::MachHeader32(unsafe {
                        mem::transmute(input.as_ptr())
                    }),
                    phantom: PhantomData,
                })
            }

            // 32 bit, big endian.
            loader::MH_CIGAM => {
                Ok(Header {
                    endian: Endian::Big,
                    raw_header: RawHeader::MachHeader32(unsafe {
                        mem::transmute(input.as_ptr())
                    }),
                    phantom: PhantomData,
                })
            }

            // 64 bit, little endian,
            loader::MH_MAGIC_64 => {
                if input.len() < mem::size_of::<loader::mach_header_64>() {
                    return Err(Error::InputNotLongEnough);
                }

                Ok(Header {
                    endian: Endian::Little,
                    raw_header: RawHeader::MachHeader64(unsafe {
                        mem::transmute(input.as_ptr())
                    }),
                    phantom: PhantomData,
                })
            }

            // 64 bit, big endian.
            loader::MH_CIGAM_64 => {
                if input.len() < mem::size_of::<loader::mach_header_64>() {
                    return Err(Error::InputNotLongEnough);
                }

                Ok(Header {
                    endian: Endian::Big,
                    raw_header: RawHeader::MachHeader64(unsafe {
                        mem::transmute(input.as_ptr())
                    }),
                    phantom: PhantomData,
                })
            }

            // Unknown magic header value.
            _ => Err(Error::UnknownMagicHeaderValue),
        }
    }

    /// Get the magic value for this header.
    pub fn magic(&self) -> u32 {
        unsafe {
            match self.raw_header {
                RawHeader::MachHeader32(h) => h.as_ref().map(|h| h.magic).unwrap(),
                RawHeader::MachHeader64(h) => h.as_ref().map(|h| h.magic).unwrap(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mach_o_sys::loader;

    const LITTLE_ENDIAN_HEADER_64: [u8; 32] = [0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01,
                                               0x03, 0x00, 0x00, 0x80, 0x02, 0x00, 0x00, 0x00,
                                               0x12, 0x00, 0x00, 0x00, 0xd8, 0x08, 0x00, 0x00,
                                               0x85, 0x80, 0xa1, 0x00, 0x00, 0x00, 0x00, 0x00];

    #[test]
    fn test_read_header() {
        let buf = &LITTLE_ENDIAN_HEADER_64;
        let header = Header::new(buf).expect("Should parse the header OK");
        assert_eq!(header.endian, Endian::Little);
        assert_eq!(header.magic(), loader::MH_MAGIC_64);
    }
}
