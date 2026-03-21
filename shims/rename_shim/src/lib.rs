//! LD_PRELOAD shim that intercepts rename/renameat/renameat2 and handles EXDEV
//! by falling back to recursive copy + delete. This fixes directory renames on
//! unprivileged overlayfs where redirect_dir=nofollow is enforced.
//!
//! Built as a tiny #[no_std] cdylib (~4KB) to minimise overhead — every process
//! in the container loads this .so.

#![no_std]

extern crate libc;

use core::ffi::c_int;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};
use libc::{
    c_char, c_void, closedir, dirent, lstat, mkdir, mode_t, readdir, readlink, rmdir,
    stat as stat_t, symlink, unlink, AT_FDCWD, EXDEV, S_IFDIR, S_IFMT, S_IFLNK,
};

// Cached function pointers to the real libc implementations.
static REAL_RENAME: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static REAL_RENAMEAT: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static REAL_RENAMEAT2: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

type RenameFn = unsafe extern "C" fn(*const c_char, *const c_char) -> c_int;
type RenameAtFn = unsafe extern "C" fn(c_int, *const c_char, c_int, *const c_char) -> c_int;
type RenameAt2Fn =
    unsafe extern "C" fn(c_int, *const c_char, c_int, *const c_char, libc::c_uint) -> c_int;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { libc::abort() }
}

unsafe fn resolve<F>(slot: &AtomicPtr<c_void>, name: &[u8]) -> F {
    let mut p = slot.load(Ordering::Relaxed);
    if p.is_null() {
        p = unsafe { libc::dlsym(libc::RTLD_NEXT, name.as_ptr().cast()) };
        slot.store(p, Ordering::Relaxed);
    }
    unsafe { core::mem::transmute_copy(&p) }
}

// ── Interposed entry points ────────────────────────────────────────

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rename(old: *const c_char, new: *const c_char) -> c_int {
    let real: RenameFn = unsafe { resolve(&REAL_RENAME, b"rename\0") };
    let ret = unsafe { real(old, new) };
    if ret == -1 && unsafe { *libc::__errno_location() } == EXDEV && is_dir_path(old) {
        return exdev_fallback(old, new);
    }
    ret
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn renameat(
    olddirfd: c_int,
    old: *const c_char,
    newdirfd: c_int,
    new: *const c_char,
) -> c_int {
    let real: RenameAtFn = unsafe { resolve(&REAL_RENAMEAT, b"renameat\0") };
    let ret = unsafe { real(olddirfd, old, newdirfd, new) };
    if ret == -1
        && unsafe { *libc::__errno_location() } == EXDEV
        && olddirfd == AT_FDCWD
        && newdirfd == AT_FDCWD
        && is_dir_path(old)
    {
        return exdev_fallback(old, new);
    }
    ret
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn renameat2(
    olddirfd: c_int,
    old: *const c_char,
    newdirfd: c_int,
    new: *const c_char,
    flags: libc::c_uint,
) -> c_int {
    let real: RenameAt2Fn = unsafe { resolve(&REAL_RENAMEAT2, b"renameat2\0") };
    let ret = unsafe { real(olddirfd, old, newdirfd, new, flags) };
    if ret == -1
        && unsafe { *libc::__errno_location() } == EXDEV
        && flags == 0
        && olddirfd == AT_FDCWD
        && newdirfd == AT_FDCWD
        && is_dir_path(old)
    {
        return exdev_fallback(old, new);
    }
    ret
}

// ── EXDEV fallback: recursive copy then delete ─────────────────────

/// Check if the path points to a directory (follows symlinks — same as rename).
fn is_dir_path(path: *const c_char) -> bool {
    let mut st: stat_t = unsafe { core::mem::zeroed() };
    // stat (not lstat) follows symlinks, matching rename(2) semantics.
    unsafe { libc::stat(path, &mut st) == 0 && (st.st_mode & S_IFMT) == S_IFDIR }
}

/// Copy source tree to dest, then remove source. Returns 0 on success, -1 on error.
/// Uses a staging name to avoid data loss if remove_tree fails partway through.
fn exdev_fallback(src: *const c_char, dst: *const c_char) -> c_int {
    // Stage 1: copy to a temporary name next to the real destination.
    // If the copy or the source removal fails, we clean up the staging copy
    // and leave the source intact.
    let mut staging = [0u8; 4096];
    {
        let mut i = 0usize;
        let mut p = dst as *const u8;
        while unsafe { *p } != 0 {
            if i >= 4080 {
                unsafe { *libc::__errno_location() = libc::ENAMETOOLONG };
                return -1;
            }
            staging[i] = unsafe { *p };
            i += 1;
            p = unsafe { p.add(1) };
        }
        // Append ".~hb~" suffix as staging marker.
        for &b in b".~hb~" {
            staging[i] = b;
            i += 1;
        }
        staging[i] = 0;
    }

    if copy_tree(src, staging.as_ptr().cast()) != 0 {
        let saved = unsafe { *libc::__errno_location() };
        remove_tree(staging.as_ptr().cast());
        unsafe { *libc::__errno_location() = saved };
        return -1;
    }

    // Stage 2: remove the source. If this fails, remove the staging copy
    // so the source is left untouched.
    if remove_tree(src) != 0 {
        let saved = unsafe { *libc::__errno_location() };
        remove_tree(staging.as_ptr().cast());
        unsafe { *libc::__errno_location() = saved };
        return -1;
    }

    // Stage 3: atomic rename staging → final destination.
    let real: RenameFn = unsafe { resolve(&REAL_RENAME, b"rename\0") };
    if unsafe { real(staging.as_ptr().cast(), dst) } != 0 {
        // rename failed — try to restore source from staging
        let saved = unsafe { *libc::__errno_location() };
        let _: RenameFn = unsafe { resolve(&REAL_RENAME, b"rename\0") };
        let _ = unsafe { real(staging.as_ptr().cast(), src) };
        unsafe { *libc::__errno_location() = saved };
        return -1;
    }

    0
}

/// Recursively copy src to dst, preserving symlinks and permissions.
fn copy_tree(src: *const c_char, dst: *const c_char) -> c_int {
    let mut st: stat_t = unsafe { core::mem::zeroed() };
    if unsafe { lstat(src, &mut st) } != 0 {
        return -1;
    }

    let mode = st.st_mode & S_IFMT;

    if mode == S_IFLNK {
        return copy_symlink(src, dst);
    }

    if mode == S_IFDIR {
        return copy_dir(src, dst, st.st_mode);
    }

    if mode == libc::S_IFREG {
        return copy_file(src, dst, st.st_mode);
    }

    // Special files (FIFO, device, socket): recreate with mknod.
    unsafe { libc::mknod(dst, st.st_mode, st.st_rdev) }
}

fn copy_symlink(src: *const c_char, dst: *const c_char) -> c_int {
    let mut buf = [0u8; 4096];
    let len = unsafe { readlink(src, buf.as_mut_ptr().cast(), buf.len() - 1) };
    if len < 0 {
        return -1;
    }
    buf[len as usize] = 0;
    unsafe { symlink(buf.as_ptr().cast(), dst) }
}

fn copy_dir(src: *const c_char, dst: *const c_char, mode: mode_t) -> c_int {
    if unsafe { mkdir(dst, mode & 0o7777) } != 0 && unsafe { *libc::__errno_location() } != libc::EEXIST {
        return -1;
    }

    // Open with O_DIRECTORY | O_NOFOLLOW to prevent TOCTOU dir→symlink swap.
    let fd = unsafe { libc::open(src, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW) };
    if fd < 0 {
        return -1;
    }
    let dir = unsafe { libc::fdopendir(fd) };
    if dir.is_null() {
        unsafe { libc::close(fd) };
        return -1;
    }

    let mut ret = 0;
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let entry: *mut dirent = unsafe { readdir(dir) };
        if entry.is_null() {
            break;
        }
        let name = unsafe { &(*entry).d_name };

        // Skip "." and ".."
        if name[0] == b'.' as i8 && (name[1] == 0 || (name[1] == b'.' as i8 && name[2] == 0)) {
            continue;
        }

        let mut child_src = [0u8; 4096];
        let mut child_dst = [0u8; 4096];
        if !join_path(src, name.as_ptr(), &mut child_src)
            || !join_path(dst, name.as_ptr(), &mut child_dst)
        {
            unsafe { *libc::__errno_location() = libc::ENAMETOOLONG };
            ret = -1;
            break;
        }

        if copy_tree(child_src.as_ptr().cast(), child_dst.as_ptr().cast()) != 0 {
            ret = -1;
            break;
        }
    }
    unsafe { closedir(dir) };
    ret
}

fn copy_file(src: *const c_char, dst: *const c_char, mode: mode_t) -> c_int {
    let fd_in = unsafe { libc::open(src, libc::O_RDONLY | libc::O_NOFOLLOW) };
    if fd_in < 0 {
        return -1;
    }
    let fd_out = unsafe {
        libc::open(
            dst,
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW,
            mode & 0o7777,
        )
    };
    if fd_out < 0 {
        unsafe { libc::close(fd_in) };
        return -1;
    }

    let mut ret = 0;
    loop {
        let n = unsafe { libc::sendfile(fd_out, fd_in, ptr::null_mut(), 0x7fff_f000) };
        if n < 0 {
            ret = -1;
            break;
        }
        if n == 0 {
            break;
        }
    }

    unsafe {
        libc::close(fd_in);
        libc::close(fd_out);
    }
    ret
}

/// Recursively remove a directory tree.
fn remove_tree(path: *const c_char) -> c_int {
    let mut st: stat_t = unsafe { core::mem::zeroed() };
    if unsafe { lstat(path, &mut st) } != 0 {
        return -1;
    }

    if (st.st_mode & S_IFMT) != S_IFDIR {
        return unsafe { unlink(path) };
    }

    let fd = unsafe { libc::open(path, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW) };
    if fd < 0 {
        return -1;
    }
    let dir = unsafe { libc::fdopendir(fd) };
    if dir.is_null() {
        unsafe { libc::close(fd) };
        return -1;
    }

    let mut ret = 0;
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { readdir(dir) };
        if entry.is_null() {
            break;
        }
        let name = unsafe { &(*entry).d_name };

        if name[0] == b'.' as i8 && (name[1] == 0 || (name[1] == b'.' as i8 && name[2] == 0)) {
            continue;
        }

        let mut child = [0u8; 4096];
        if !join_path(path, name.as_ptr(), &mut child) {
            unsafe { *libc::__errno_location() = libc::ENAMETOOLONG };
            ret = -1;
            break;
        }
        if remove_tree(child.as_ptr().cast()) != 0 {
            ret = -1;
            break;
        }
    }
    unsafe { closedir(dir) };

    if ret == 0 {
        ret = unsafe { rmdir(path) };
    }
    ret
}

// ── Path helpers (no allocator) ────────────────────────────────────

/// Join dir + "/" + name into buf. Returns false if the result would overflow PATH_MAX.
fn join_path(dir: *const c_char, name: *const c_char, buf: &mut [u8; 4096]) -> bool {
    let mut i = 0;

    let mut p = dir as *const u8;
    while unsafe { *p } != 0 {
        if i >= 4094 {
            return false;
        }
        buf[i] = unsafe { *p };
        i += 1;
        p = unsafe { p.add(1) };
    }
    if i > 0 && buf[i - 1] != b'/' {
        buf[i] = b'/';
        i += 1;
    }
    p = name as *const u8;
    while unsafe { *p } != 0 {
        if i >= 4095 {
            return false;
        }
        buf[i] = unsafe { *p };
        i += 1;
        p = unsafe { p.add(1) };
    }
    buf[i] = 0;
    true
}
