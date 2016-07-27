extern crate mach_o;

use std::env;
use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

fn hexdump(addr: usize, slice: &[u8]) {
    for (idx, chunk) in slice.chunks(16).enumerate() {
        print!("{:016x} \t", idx * 16 + addr);
        for byte in chunk {
            print!("{:02x} ", byte);
        }
        print!("\n");
    }
}

// The output of this test should be the same as this command:
//
//     $ otool -s __DWARF __debug_abbrev test-mach-o-file
#[test]
fn test_get_debug_info() {
    let mut path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    path.push("./tests/test-mach-o-file");

    assert!(path.is_file());
    let mut file = File::open(path).unwrap();

    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();

    let header = mach_o::Header::new(&buf);
    let header = header.expect("Should parse header OK");

    let segment_name = CString::new("__DWARF").unwrap();
    let section_name = CString::new("__debug_info").unwrap();

    let debug_info = header.get_section(&segment_name, &section_name);
    let debug_info = debug_info.expect("Should have a __debug_info section");

    assert_eq!(debug_info.name(), section_name.as_ref());
    assert_eq!(debug_info.segment_name(), segment_name.as_ref());

    hexdump(debug_info.addr() as usize, debug_info.data());
}
