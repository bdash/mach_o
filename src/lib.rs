//! A Rust API for working with OSX's Mach-O object files.

#![deny(missing_docs)]

extern crate mach_o_sys;

use mach_o_sys::{loader, getsect};
use std::ffi::CStr;
use std::mem;

/// An error that occurred while parsing the mach-o file contents.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// The input is not long enough to contain valid contents.
    InputNotLongEnough,
    /// Found an unknown magic header value.
    UnknownMagicHeaderValue,
}

#[derive(Copy, Clone, Debug)]
enum RawHeader {
    MachHeader32(*const loader::mach_header),
    MachHeader64(*const loader::mach_header_64),
}

/// A mach-o file header.
#[derive(Copy, Clone, Debug)]
pub struct Header<'a> {
    raw_header: RawHeader,
    input: &'a [u8],
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
            // 32 bit.
            loader::MH_MAGIC | loader::MH_CIGAM => {
                Ok(Header {
                    raw_header: RawHeader::MachHeader32(unsafe { mem::transmute(input.as_ptr()) }),
                    input: input,
                })
            }

            // 64 bit.
            loader::MH_MAGIC_64 |
            loader::MH_CIGAM_64 => {
                if input.len() < mem::size_of::<loader::mach_header_64>() {
                    return Err(Error::InputNotLongEnough);
                }

                Ok(Header {
                    raw_header: RawHeader::MachHeader64(unsafe { mem::transmute(input.as_ptr()) }),
                    input: input,
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
                RawHeader::MachHeader32(h) => h.as_ref().unwrap().magic,
                RawHeader::MachHeader64(h) => h.as_ref().unwrap().magic,
            }
        }
    }

    /// Get the data for a given section, if it exists.
    pub fn get_section(&self, segment_name: &CStr, section_name: &CStr) -> Option<Section<'a>> {
        unsafe {
            match self.raw_header {
                RawHeader::MachHeader32(h) => {
                    let h: *mut getsect::mach_header = mem::transmute(h);
                    let section = if self.magic() == loader::MH_MAGIC {
                        getsect::getsectbynamefromheader(h,
                                                         segment_name.as_ptr(),
                                                         section_name.as_ptr())
                    } else {
                        assert_eq!(self.magic(), loader::MH_CIGAM);
                        getsect::getsectbynamefromheaderwithswap(h,
                                                                 segment_name.as_ptr(),
                                                                 section_name.as_ptr(),
                                                                 1)
                    };

                    match section.as_ref() {
                        None => None,
                        Some(section) => {
                            Some(Section {
                                raw_section: RawSection::Section32(section),
                                input: self.input,
                            })
                        }
                    }
                }
                RawHeader::MachHeader64(h) => {
                    let h: *mut getsect::mach_header_64 = mem::transmute(h);
                    let section = if self.magic() == loader::MH_MAGIC_64 {
                        getsect::getsectbynamefromheader_64(h,
                                                            segment_name.as_ptr(),
                                                            section_name.as_ptr())
                    } else {
                        assert_eq!(self.magic(), loader::MH_CIGAM_64);
                        let section =
                            getsect::getsectbynamefromheaderwithswap_64(h,
                                                                        segment_name.as_ptr(),
                                                                        section_name.as_ptr(),
                                                                        1);
                        mem::transmute(section)
                    };

                    match section.as_ref() {
                        None => None,
                        Some(section) => {
                            Some(Section {
                                raw_section: RawSection::Section64(section),
                                input: self.input,
                            })
                        }
                    }
                }
            }
        }
    }
}

#[derive(Copy, Clone, Debug)]
enum RawSection {
    Section32(*const getsect::section),
    Section64(*const getsect::section_64),
}

/// A section in the mach-o file.
#[derive(Copy, Clone, Debug)]
pub struct Section<'a> {
    raw_section: RawSection,
    input: &'a [u8],
}

impl<'a> Section<'a> {
    /// Get this section's name.
    pub fn name(&self) -> &CStr {
        unsafe {
            match self.raw_section {
                RawSection::Section32(s) => {
                    CStr::from_ptr(mem::transmute(&s.as_ref().unwrap().sectname))
                }
                RawSection::Section64(s) => {
                    CStr::from_ptr(mem::transmute(&s.as_ref().unwrap().sectname))
                }
            }
        }
    }

    /// Get this section's segment's name.
    pub fn segment_name(&self) -> &CStr {
        unsafe {
            match self.raw_section {
                RawSection::Section32(s) => {
                    CStr::from_ptr(mem::transmute(&s.as_ref().unwrap().segname))
                }
                RawSection::Section64(s) => {
                    CStr::from_ptr(mem::transmute(&s.as_ref().unwrap().segname))
                }
            }
        }
    }

    /// Get this section's vm address.
    pub fn addr(&self) -> u64 {
        unsafe {
            match self.raw_section {
                RawSection::Section32(s) => s.as_ref().unwrap().addr as u64,
                RawSection::Section64(s) => s.as_ref().unwrap().addr,
            }
        }
    }

    /// Get this section's data.
    pub fn data(&self) -> &'a [u8] {
        unsafe {
            match self.raw_section {
                RawSection::Section32(s) => {
                    let s = s.as_ref().unwrap();
                    let start = s.offset as usize;
                    let end = start + s.size as usize;
                    &self.input[start..end]
                }
                RawSection::Section64(s) => {
                    let s = s.as_ref().unwrap();
                    let start = s.offset as usize;
                    let end = start + s.size as usize;
                    &self.input[start..end]
                }
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
        assert_eq!(header.magic(), loader::MH_MAGIC_64);
    }
}
