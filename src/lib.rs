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

/// Implementation of the [`primitives`] interface for the user space using the standard library.
#[cfg(feature = "std")]
pub mod userspace;

/// This module contains the primitives that need to be implemented to enable the usage of this
/// library in a program environment.
///
/// An implementation for the user space is provided in [`userspace`] and can be enabled
/// with the `std` feature.
pub mod primitives;

mod spinlock;

pub fn test() {
    unsafe {
        primitives::zan_write(ptr::null(), 0);
    }
}

