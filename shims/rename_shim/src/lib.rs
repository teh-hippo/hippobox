//! LD_PRELOAD shim: intercepts rename/renameat/renameat2 and handles EXDEV by
//! falling back to recursive copy + delete (fixes directory renames on unprivileged overlayfs).
//!
//! This shim only works on Linux (LD_PRELOAD + glibc). On non-Unix platforms
//! the crate compiles as an empty cdylib.
#![cfg_attr(unix, no_std)]

#[cfg(unix)]
mod imp;
