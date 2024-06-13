use core::ffi::*;
use core::fmt::Display;
use core::mem;

use crate::primitives::*;
use crate::spinlock::Spinlock;
use crate::eprint;
use crate::eprintln;




static LOCK: Spinlock = Spinlock::new();
const PROLOGUE_HEADER: &str = "=== UNDEFINED BEHAVIOUR DETECTED ===";
const TYPE_CHECK_KINDS: [&str; 8] = [
    "load of",
    "store to",
    "reference binding to",
    "member access within",
    "member call on",
    "constructor call on",
    "downcast of",
    "downcast of",
];



#[allow(dead_code)]
#[derive(Clone, Copy)]
#[repr(u16)]
pub enum TypeKind {
    Int = 0,
    Float = 1,
    Unknown = 0xffff,
}

#[derive(Clone)]
#[repr(C)]
pub struct SourceLocation {
    filename: *const c_char,
    line: u32,
    column: u32,
}

#[derive(Clone)]
#[repr(C)]
pub struct TypeDescriptor {
    type_kind: u16,
    type_info: u16,
    type_name: *const c_char,
}

// DATA STRUCTS

#[repr(C)]
pub struct FunctionTypeMismatchData {
    location: SourceLocation,
    data_type: TypeDescriptor,
}

#[repr(C)]
pub struct InvalidBuiltinData {
    location: SourceLocation,
    kind: u8,
}

#[repr(C)]
pub struct InvalidValueData {
    location: SourceLocation,
    data_type: TypeDescriptor,
}

#[repr(C)]
pub struct NonnullArgData {
    location: SourceLocation,
    attr_location: SourceLocation,
    arg_index: u32,
}

#[repr(C)]
pub struct OutOfBoundsData {
    location: SourceLocation,
    array_type: TypeDescriptor,
    index_type: TypeDescriptor,
}

#[repr(C)]
pub struct OverflowData {
    location: SourceLocation,
    data_type: TypeDescriptor,
}

#[repr(C)]
pub struct PointerOverflowData {
    location: SourceLocation,
}

#[repr(C)]
pub struct ShiftOutOfBoundsData {
    location: SourceLocation,
    lhs_type: TypeDescriptor,
    rhs_type: TypeDescriptor,
}

#[repr(C)]
pub struct TypeMismatchData {
    location: SourceLocation,
    data_type: TypeDescriptor,
    alignment: u64,
    type_check_kind: u8,
}

#[repr(C)]
pub struct TypeMismatchDataV1 {
    location: SourceLocation,
    data_type: TypeDescriptor,
    log_alignment: u8,
    type_check_kind: u8,
}

#[repr(C)]
pub struct UnreachableData {
    location: SourceLocation,
    data_type: TypeDescriptor,
    alignment: u64,
    type_check_kind: u8,
}


impl TypeDescriptor {
    pub fn bit_width(&self) -> usize {
        1 << (self.type_info >> 1)
    }

    pub fn is_inline_int(&self) -> bool {
        self.bit_width() <= (mem::size_of::<c_ulong>() * 8)
    }

    pub fn is_int(&self) -> bool {
        self.type_kind == TypeKind::Int as u16
    }

    pub fn is_signed(&self) -> bool {
        self.type_info & 1 != 0
    }

    pub fn is_signed_int(&self) -> bool {
        self.is_int() && self.is_signed()
    }

    pub fn is_negative(&self, val: *const c_void) -> bool {
        self.is_signed() && self.signed_value(val) < 0
    }

    pub fn is_unsigned_int(&self) -> bool {
        self.is_int() && !self.is_signed()
    }

    pub fn signed_value(&self, val: *const c_void) -> i64 {
        if self.is_inline_int() {
            let extra_bits = mem::size_of::<i64>() * 8 - self.bit_width();
            let u64_val = val as u64;
            return (u64_val as i64) << extra_bits >> extra_bits;
        }

        unsafe { *(val as *const i64) }
    }

    pub fn unsigned_value(&self, val: *const c_void) -> u64 {
        if self.is_inline_int() {
            return val as u64;
        }

        unsafe { *(val as *const u64) }
    }

    pub fn print_data(&self, val: *const c_void) {
        if self.is_signed_int() {
            let ival = self.signed_value(val);
            eprint!("{}", ival);
        } else if self.is_unsigned_int() {
            let uval = self.unsigned_value(val);
            eprint!("{}", uval);
        } else {
            eprint!("?");
        }
    }
}

impl Display for TypeDescriptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        unsafe {
            if let Ok(label) = CStr::from_ptr(self.type_name).to_str() {
                write!(f, "{}", label)
            } else {
                write!(f, "unknown")
            }
        }
    }
}



// COMMON HELPER FUNCTIONS

fn prologue(location: &SourceLocation, reason: &str) {
    unsafe {
        // disable interrupts and grab lock to ensure coherent output
        zan_disable_interrupts();
        LOCK.lock();
    }

    let filename = unsafe {
        CStr::from_ptr(location.filename).to_str().unwrap()
    };

    eprintln!();
    eprintln!("{}", PROLOGUE_HEADER);
    eprintln!("{} in {}:{}:{}", reason, filename, location.line, location.column);
}

fn epilogue() {
    for _ in 0..PROLOGUE_HEADER.len() {
        eprint!("=");
    }
    eprintln!();
    LOCK.release();

    unsafe {
        zan_abort();
    }
}

unsafe fn handle_function_type_mismatch(data: *const FunctionTypeMismatchData, ptr: usize) {
    prologue(&(*data).location, "function-type-mismatch");
    eprintln!("call to function {:x} through pointer to incorrect function type", ptr);
    epilogue();
}

unsafe fn handle_overflow(data: *const OverflowData, lhs: *const c_void, rhs: *const c_void, op: &str, reason: &str) {
    prologue(&(*data).location, reason);

    eprint!("operation '");
    (*data).data_type.print_data(lhs);
    eprint!(" {} ", op);
    (*data).data_type.print_data(rhs);
    eprint!("' cannot be represented in type {}", (*data).data_type);

    epilogue();
}

unsafe fn handle_type_mismatch(data: *const TypeMismatchData, ptr: usize) {
    if ptr == 0 {
        prologue(&(*data).location, "null-ptr-deref");
        eprint!("{} null pointer of type {}", TYPE_CHECK_KINDS[(*data).type_check_kind as usize], (*data).data_type);
        epilogue();
    } else if (*data).alignment != 0 && (ptr % (*data).alignment as usize != 0) {
        prologue(&(*data).location, "misaligned-access");
        eprint!("{} misaligned address {} for type {}", TYPE_CHECK_KINDS[(*data).type_check_kind as usize], ptr, (*data).data_type);
        epilogue();
    } else {
        prologue(&(*data).location, "object-size-mismatch");
        eprint!("{} address {} with insufficient space", TYPE_CHECK_KINDS[(*data).type_check_kind as usize], ptr);
        epilogue();
    }
}


// UBSAN ROUTINES



/// # Safety
///
/// This function should not be called by any other than the UndefinedBehaviorSanitizer
#[no_mangle]
pub unsafe extern "C" fn __ubsan_handle_builtin_unreachable(data: *const UnreachableData) {
    assert!(!data.is_null());
    prologue(&(*data).location, "unreachable");
    eprintln!("calling __builtin_unreachable()");
    epilogue();
}

/// # Safety
///
/// This function should not be called by any other than the UndefinedBehaviorSanitizer
#[no_mangle]
pub unsafe extern "C" fn __ubsan_handle_invalid_builtin(data: *const InvalidBuiltinData) {
    assert!(!data.is_null());
    prologue(&(*data).location, "builtin");
    eprintln!("invalid value passed to compiler builtin");
    epilogue();
}

/// # Safety
///
/// This function should not be called by any other than the UndefinedBehaviorSanitizer
#[no_mangle]
pub unsafe extern "C" fn __ubsan_handle_divrem_overflow(data: *const OverflowData, lhs: *const c_void, rhs: *const c_void) {
    assert!(!data.is_null());
    handle_overflow(data, lhs, rhs, "divrem", "division-overflow");
}

/// # Safety
///
/// This function should not be called by any other than the UndefinedBehaviorSanitizer
#[no_mangle]
pub unsafe extern "C" fn __ubsan_handle_function_type_mismatch(data: *const FunctionTypeMismatchData, ptr: usize) {
    assert!(!data.is_null());
    handle_function_type_mismatch(data, ptr)
}

/// # Safety
///
/// This function should not be called by any other than the UndefinedBehaviorSanitizer
#[no_mangle]
pub unsafe extern "C" fn __ubsan_handle_load_invalid_value(data: *const InvalidValueData, val: *const c_void) {
    assert!(!data.is_null());
    prologue(&(*data).location, "invalid-load");

    eprint!("load of value ");
    (*data).data_type.print_data(val);
    eprintln!("is not a valid value for type {}", (*data).data_type);

    epilogue();
}

/// # Safety
///
/// This function should not be called by any other than the UndefinedBehaviorSanitizer
#[no_mangle]
pub unsafe extern "C" fn __ubsan_handle_mul_overflow(data: *const OverflowData, lhs: *const c_void, rhs: *const c_void) {
    assert!(!data.is_null());
    handle_overflow(data, lhs, rhs, "*", "multiplication-overflow");
}

/// # Safety
///
/// This function should not be called by any other than the UndefinedBehaviorSanitizer
#[no_mangle]
pub unsafe extern "C" fn __ubsan_handle_negate_overflow(data: *const OverflowData, val: u64) {
    assert!(!data.is_null());
    prologue(&(*data).location, "negate-overflow");
    eprintln!("negation of {} cannot be represented in type {}", val, (*data).data_type);
    epilogue();
}

/// # Safety
///
/// This function should not be called by any other than the UndefinedBehaviorSanitizer
#[no_mangle]
pub unsafe extern "C" fn __ubsan_handle_nonnull_arg(data: *const NonnullArgData) {
    assert!(!data.is_null());
    prologue(&(*data).location, "nonnull-arg");
    eprintln!("null pointer was passed as argument {}, which is defined to never be null", (*data).arg_index);
    epilogue();
}

/// # Safety
///
/// This function should not be called by any other than the UndefinedBehaviorSanitizer
#[no_mangle]
pub unsafe extern "C" fn __ubsan_handle_out_of_bounds(data: *const OutOfBoundsData, index: *const c_void) {
    assert!(!data.is_null());
    prologue(&(*data).location, "array-index-out-of-bounds");

    eprint!("index ");
    (*data).index_type.print_data(index);
    eprintln!(" is out of range for type {}", (*data).array_type);

    epilogue();
}

/// # Safety
///
/// This function should not be called by any other than the UndefinedBehaviorSanitizer
#[no_mangle]
pub unsafe extern "C" fn __ubsan_handle_pointer_overflow(data: *const PointerOverflowData, base: usize, result: usize) {
    assert!(!data.is_null());
    prologue(&(*data).location, "pointer-overflow");
    eprintln!("pointer expression with base {} overflowed to {}", base, result);
    epilogue();
}

/// # Safety
///
/// This function should not be called by any other than the UndefinedBehaviorSanitizer
#[no_mangle]
pub unsafe extern "C" fn __ubsan_handle_shift_out_of_bounds(data: *const ShiftOutOfBoundsData, lhs: *const c_void, rhs: *const c_void) {
    assert!(!data.is_null());
    prologue(&(*data).location, "shift-out-of-bounds");

    let lhs_type = &(*data).lhs_type;
    let rhs_type = &(*data).rhs_type;

    eprint!("Lhs: \t\t");
    lhs_type.print_data(lhs);
    eprintln!();

    eprint!("Rhs: \t\t");
    rhs_type.print_data(rhs);
    eprintln!();

    if rhs_type.is_negative(rhs) {
        eprint!("shift exponent ");
        rhs_type.print_data(rhs);
        eprintln!(" is negative");
    } else if rhs_type.unsigned_value(rhs) >= rhs_type.bit_width() as u64 {
        eprint!("shift exponent ");
        rhs_type.print_data(rhs);
        eprintln!(" is too large for {}-bit type {}", rhs_type.bit_width(), rhs_type);
    } else if lhs_type.is_negative(lhs) {
        eprint!("left shift of negative value ");
        lhs_type.print_data(lhs);
        eprintln!();
    } else {
        eprint!("left shift of ");
        lhs_type.print_data(lhs);
        eprint!(" by ");
        rhs_type.print_data(rhs);
        eprintln!(" cannot be represented in type {}", lhs_type);
    }

    epilogue();
}

/// # Safety
///
/// This function should not be called by any other than the UndefinedBehaviorSanitizer
#[no_mangle]
pub unsafe extern "C" fn __ubsan_handle_type_mismatch(data: *const TypeMismatchData, ptr: usize) {
    assert!(!data.is_null());
    handle_type_mismatch(data, ptr);
}

/// # Safety
///
/// This function should not be called by any other than the UndefinedBehaviorSanitizer
#[no_mangle]
pub unsafe extern "C" fn __ubsan_handle_type_mismatch_v1(data: *const TypeMismatchDataV1, ptr: usize) {
    assert!(!data.is_null());
    let data = TypeMismatchData {
        location: (*data).location.clone(),
        data_type: (*data).data_type.clone(),
        alignment: 1 << (*data).log_alignment,
        type_check_kind: (*data).type_check_kind,
    };
    handle_type_mismatch(&data, ptr);
}
