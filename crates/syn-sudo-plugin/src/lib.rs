//! Classic sudo approval plug-in.
//!
//! The Linux implementation is deliberately isolated behind `cfg` so the shared
//! protocol can be developed on macOS without pretending the plug-in is usable
//! there. The exported ABI never unwinds and never executes a command.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_os = "linux")]
mod cancellation;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::syn_approval;

#[cfg(not(target_os = "linux"))]
#[no_mangle]
pub static syn_approval_non_linux_build_marker: u32 = 1;
