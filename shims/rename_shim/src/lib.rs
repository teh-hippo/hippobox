//! LD_PRELOAD shim: intercepts rename/renameat/renameat2 and handles EXDEV by
//! falling back to recursive copy + delete (fixes directory renames on unprivileged overlayfs).

#![no_std]

extern crate libc;

use core::ffi::c_int;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};
use libc::{
    c_char, c_void, closedir, lstat, mkdir, mode_t, readdir, readlink, rmdir,
    stat as stat_t, symlink, unlink, AT_FDCWD, EXDEV, S_IFDIR, S_IFMT, S_IFLNK,
};

// Cached function pointers to the real libc implementations.
static REAL_RENAME: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static REAL_RENAMEAT: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static REAL_RENAMEAT2: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

type RenameFn = unsafe extern "C" fn(*const c_char, *const c_char) -> c_int;
type RenameAtFn = unsafe extern "C" fn(c_int, *const c_char, c_int, *const c_char) -> c_int;
type RenameAt2Fn = unsafe extern "C" fn(c_int, *const c_char, c_int, *const c_char, libc::c_uint) -> c_int;

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
    olddirfd: c_int, old: *const c_char, newdirfd: c_int, new: *const c_char,
) -> c_int {
    let real: RenameAtFn = unsafe { resolve(&REAL_RENAMEAT, b"renameat\0") };
    let ret = unsafe { real(olddirfd, old, newdirfd, new) };
    if ret == -1 && unsafe { *libc::__errno_location() } == EXDEV
        && olddirfd == AT_FDCWD && newdirfd == AT_FDCWD && is_dir_path(old)
    { return exdev_fallback(old, new); }
    ret
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn renameat2(
    olddirfd: c_int, old: *const c_char, newdirfd: c_int, new: *const c_char, flags: libc::c_uint,
) -> c_int {
    let real: RenameAt2Fn = unsafe { resolve(&REAL_RENAMEAT2, b"renameat2\0") };
    let ret = unsafe { real(olddirfd, old, newdirfd, new, flags) };
    if ret == -1 && unsafe { *libc::__errno_location() } == EXDEV
        && flags == 0 && olddirfd == AT_FDCWD && newdirfd == AT_FDCWD && is_dir_path(old)
    { return exdev_fallback(old, new); }
    ret
}

fn is_dir_path(path: *const c_char) -> bool {
    let mut st: stat_t = unsafe { core::mem::zeroed() };
    unsafe { libc::stat(path, &mut st) == 0 && (st.st_mode & S_IFMT) == S_IFDIR }
}

/// Copy source tree to dest, then remove source via staging name for atomicity.
fn exdev_fallback(src: *const c_char, dst: *const c_char) -> c_int {
    let mut staging = [0u8; 4096];
    let i = copy_cstr(dst, &mut staging, 0, 4080);
    if i == 0 {
        unsafe { *libc::__errno_location() = libc::ENAMETOOLONG };
        return -1;
    }
    let mut i = i;
    for &b in b".~hb~" { staging[i] = b; i += 1; }
    staging[i] = 0;

    if copy_tree(src, staging.as_ptr().cast()) != 0 {
        let saved = unsafe { *libc::__errno_location() };
        remove_tree(staging.as_ptr().cast());
        unsafe { *libc::__errno_location() = saved };
        return -1;
    }

    if remove_tree(src) != 0 {
        let saved = unsafe { *libc::__errno_location() };
        remove_tree(staging.as_ptr().cast());
        unsafe { *libc::__errno_location() = saved };
        return -1;
    }

    let real: RenameFn = unsafe { resolve(&REAL_RENAME, b"rename\0") };
    if unsafe { real(staging.as_ptr().cast(), dst) } != 0 {
        let saved = unsafe { *libc::__errno_location() };
        let _ = unsafe { real(staging.as_ptr().cast(), src) };
        unsafe { *libc::__errno_location() = saved };
        return -1;
    }
    0
}

fn copy_tree(src: *const c_char, dst: *const c_char) -> c_int {
    let mut st: stat_t = unsafe { core::mem::zeroed() };
    if unsafe { lstat(src, &mut st) } != 0 { return -1; }
    match st.st_mode & S_IFMT {
        S_IFLNK => copy_symlink(src, dst),
        S_IFDIR => copy_dir(src, dst, st.st_mode),
        _ if st.st_mode & S_IFMT == libc::S_IFREG => copy_file(src, dst, st.st_mode),
        _ => unsafe { libc::mknod(dst, st.st_mode, st.st_rdev) },
    }
}

fn copy_symlink(src: *const c_char, dst: *const c_char) -> c_int {
    let mut buf = [0u8; 4096];
    let len = unsafe { readlink(src, buf.as_mut_ptr().cast(), buf.len() - 1) };
    if len < 0 { return -1; }
    buf[len as usize] = 0;
    unsafe { symlink(buf.as_ptr().cast(), dst) }
}

/// Iterate entries in a directory, calling `f(dir_path, entry_name)` for each non-dot entry.
fn for_each_child(
    dir_path: *const c_char,
    f: &mut dyn FnMut(*const c_char, *const c_char) -> c_int,
) -> c_int {
    let fd = unsafe { libc::open(dir_path, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW) };
    if fd < 0 { return -1; }
    let dir = unsafe { libc::fdopendir(fd) };
    if dir.is_null() { unsafe { libc::close(fd) }; return -1; }

    let mut ret = 0;
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { readdir(dir) };
        if entry.is_null() { break; }
        let name = unsafe { &(*entry).d_name };
        if name[0] == b'.' as i8 && (name[1] == 0 || (name[1] == b'.' as i8 && name[2] == 0)) {
            continue;
        }
        if f(dir_path, name.as_ptr()) != 0 { ret = -1; break; }
    }
    unsafe { closedir(dir) };
    ret
}

fn copy_dir(src: *const c_char, dst: *const c_char, mode: mode_t) -> c_int {
    if unsafe { mkdir(dst, mode & 0o7777) } != 0 && unsafe { *libc::__errno_location() } != libc::EEXIST {
        return -1;
    }
    let dst_raw = dst;
    for_each_child(src, &mut |parent, name| {
        let mut child_src = [0u8; 4096];
        let mut child_dst = [0u8; 4096];
        if !join_path(parent, name, &mut child_src) || !join_path(dst_raw, name, &mut child_dst) {
            unsafe { *libc::__errno_location() = libc::ENAMETOOLONG };
            return -1;
        }
        copy_tree(child_src.as_ptr().cast(), child_dst.as_ptr().cast())
    })
}

fn copy_file(src: *const c_char, dst: *const c_char, mode: mode_t) -> c_int {
    let fd_in = unsafe { libc::open(src, libc::O_RDONLY | libc::O_NOFOLLOW) };
    if fd_in < 0 { return -1; }
    let fd_out = unsafe {
        libc::open(dst, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW, mode & 0o7777)
    };
    if fd_out < 0 { unsafe { libc::close(fd_in) }; return -1; }

    let mut ret = 0;
    loop {
        let n = unsafe { libc::sendfile(fd_out, fd_in, ptr::null_mut(), 0x7fff_f000) };
        if n < 0 { ret = -1; break; }
        if n == 0 { break; }
    }
    unsafe { libc::close(fd_in); libc::close(fd_out); }
    ret
}

/// Recursively remove a directory tree.
fn remove_tree(path: *const c_char) -> c_int {
    let mut st: stat_t = unsafe { core::mem::zeroed() };
    if unsafe { lstat(path, &mut st) } != 0 { return -1; }
    if (st.st_mode & S_IFMT) != S_IFDIR { return unsafe { unlink(path) }; }

    let ret = for_each_child(path, &mut |parent, name| {
        let mut child = [0u8; 4096];
        if !join_path(parent, name, &mut child) {
            unsafe { *libc::__errno_location() = libc::ENAMETOOLONG };
            return -1;
        }
        remove_tree(child.as_ptr().cast())
    });
    if ret == 0 { unsafe { rmdir(path) } } else { ret }
}

/// Copy a C string into `buf` starting at offset `i`. Returns new offset, or 0 on overflow.
fn copy_cstr(src: *const c_char, buf: &mut [u8; 4096], mut i: usize, limit: usize) -> usize {
    let mut p = src as *const u8;
    while unsafe { *p } != 0 {
        if i >= limit { return 0; }
        buf[i] = unsafe { *p };
        i += 1;
        p = unsafe { p.add(1) };
    }
    i
}

/// Join dir + "/" + name into buf. Returns false if the result would overflow.
fn join_path(dir: *const c_char, name: *const c_char, buf: &mut [u8; 4096]) -> bool {
    let i = copy_cstr(dir, buf, 0, 4094);
    if i == 0 { return false; }
    let mut i = i;
    if i > 0 && buf[i - 1] != b'/' { buf[i] = b'/'; i += 1; }
    let i = copy_cstr(name, buf, i, 4095);
    if i == 0 { return false; }
    buf[i] = 0;
    true
}
