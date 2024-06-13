#![allow(dead_code)]

use std::io::stderr;
use std::io::Write;
use std::process::exit;
use std::slice;

#[no_mangle]
pub unsafe extern "C" fn zan_write(buffer: *const u8, nbytes: usize) {
    let buf = slice::from_raw_parts(buffer, nbytes);
    stderr().write_all(buf).unwrap();
}

#[no_mangle]
pub unsafe extern "C" fn zan_abort() {
    exit(1);
}

#[no_mangle]
// didn't find a sane way to do this without additional crates
pub fn zan_disable_interrupts() {}
