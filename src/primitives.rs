extern "C" {
    pub fn zan_write(buffer: *const u8, nbytes: usize);
    pub fn zan_abort();
    pub fn zan_disable_interrupts();
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
    unsafe {
        if let Some(str) = args.as_str() {
            zan_write(str.as_ptr(), str.as_bytes().len());
        }
    }
}

#[cfg_attr(not(feature = "std"), panic_handler)]
#[cfg(not(feature = "std"))]
fn panic(info: &core::panic::PanicInfo) -> ! {
    eprintln!("{}", info);
    unsafe { zan_abort(); }
    loop {}
}


