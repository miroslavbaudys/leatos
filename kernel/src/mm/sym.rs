//! Addresses of linker-script symbols (every arch's linker script defines
//! the same names, see kernel/linker.ld).

macro_rules! linker_symbols {
    ($($fn_name:ident => $sym:ident),* $(,)?) => {
        unsafe extern "C" { $(static $sym: u8;)* }
        $(
            #[inline]
            pub fn $fn_name() -> usize {
                // Taking the address of an extern static is safe; it is never read.
                &raw const $sym as usize
            }
        )*
    };
}

linker_symbols! {
    kernel_start => __kernel_start,
    kernel_end => __kernel_end,
    text_start => __text_start,
    text_end => __text_end,
    rodata_start => __rodata_start,
    rodata_end => __rodata_end,
    data_start => __data_start,
    data_end => __data_end,
    exc_stack_guard => __exc_stack_guard,
    exc_stack_bottom => __exc_stack_bottom,
    exc_stack_top => __exc_stack_top,
    stack_guard => __stack_guard,
    stack_bottom => __stack_bottom,
    stack_top => __stack_top,
}
