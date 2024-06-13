#![allow(dead_code)]

use std::io::stderr;
use std::io::Write;
use std::process::exit;
use std::slice;

/// Write error message to stderr
///
/// # Safety
/// This function should only be called by the library, which should ensure that the `buffer`
/// contains exactly `nbytes` bytes.
#[no_mangle]
pub unsafe extern "C" fn zan_write(buffer: *const u8, nbytes: usize) {
    let buf = slice::from_raw_parts(buffer, nbytes);
    stderr().write_all(buf).unwrap();
}

/// Abort the program by exiting with error code
#[no_mangle]
pub extern "C" fn zan_abort() {
    exit(1);
}

/// Right now this does nothing, but it would be great to disable UNIX signals for example
#[no_mangle]
pub fn zan_disable_interrupts() {}
