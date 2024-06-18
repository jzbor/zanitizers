use core::fmt::Write;

extern "C" {
/// Prints out an error message to a debug output
///
/// # Arguments
/// * `buffer`: pointer to character array containing at least `nbytes`
/// * `nbytes`: number of bytes in the buffer
pub fn zan_write(buffer: *const u8, nbytes: usize);

/// Aborts the program
pub fn zan_abort();

/// Tries to disable interrupts or signals to ensure coherent debug output
pub fn zan_disable_interrupts();
}

struct ZanWriter {}

impl ZanWriter {
    const fn new() -> Self {
        ZanWriter {}
    }
}

impl core::fmt::Write for ZanWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        unsafe { zan_write(s.as_ptr(), s.len()); }
        Ok(())
    }
}


#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => ($crate::primitives::_eprint(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! eprintln {
    () => ($crate::eprint!("\n"));
    ($($arg:tt)*) => ($crate::eprint!("{}\n", format_args!($($arg)*)));
}


#[doc(hidden)]
pub fn _eprint(args: core::fmt::Arguments) {
    let _ = write!(ZanWriter::new(), "{}", args);
}

#[cfg_attr(not(any(feature = "std", test)), panic_handler)]
#[cfg(not(any(feature = "std", test)))]
fn panic(info: &core::panic::PanicInfo) -> ! {
    eprintln!("{}", info);
    unsafe { zan_abort(); }
    loop {}
}


