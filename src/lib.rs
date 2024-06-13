#![cfg_attr(not(feature = "std"), no_std)]

use core::ptr;



/// Implementation of the [UndefinedBehaviorSanitizer interface](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html).
///
/// All documentation regarding the interface is unofficial and based on the understandinng of the
/// author(s).
///
/// The implementation is not yet complete.
/// If you find any errors or missing implementations feel free to report them.
#[cfg(feature = "ubsan")]
pub mod ubsan;
#[cfg(feature = "std")]
mod userspace;
mod primitives;
mod spinlock;

pub fn test() {
    unsafe {
        primitives::zan_write(ptr::null(), 0);
    }
}

