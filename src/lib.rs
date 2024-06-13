#![cfg_attr(not(feature = "std"), no_std)]

use core::ptr;



#[cfg(feature = "ubsan")]
mod ubsan;
#[cfg(feature = "std")]
mod userspace;
mod primitives;
mod spinlock;

pub fn test() {
    unsafe {
        primitives::zan_write(ptr::null(), 0);
    }
}

