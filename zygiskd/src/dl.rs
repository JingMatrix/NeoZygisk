// src/dl.rs

//! Provides a safe interface to Android's extended dynamic linking functionality.
//!
//! Android's linker (`/system/bin/linker`) supports creating isolated "linker namespaces"
//! for shared libraries. This allows a library and its dependencies to be loaded without
//! conflicting with other libraries in the main process. This module wraps the necessary
//! FFI calls to use this feature.

use anyhow::{Result, bail};
use std::ffi::{CStr, CString, c_char, c_void};

// --- FFI Constants and Structs for Android Linker ---

/// Flag to indicate that a shared linker namespace should be used.
pub const ANDROID_NAMESPACE_TYPE_SHARED: u64 = 0x2;

/// Flag for `android_dlopen_ext` to specify that `library_namespace` should be used.
pub const ANDROID_DLEXT_USE_NAMESPACE: u64 = 0x200;

/// An opaque handle to an Android linker namespace.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct AndroidNamespace {
    _unused: [u8; 0],
}

/// The extended information structure passed to `android_dlopen_ext`.
#[repr(C)]
pub struct AndroidDlextinfo {
    pub flags: u64,
    pub reserved_addr: *mut c_void,
    pub reserved_size: libc::size_t,
    pub relro_fd: libc::c_int,
    pub library_fd: libc::c_int,
    pub library_fd_offset: libc::off64_t,
    pub library_namespace: *mut AndroidNamespace,
}

// --- FFI Function Declarations ---
unsafe extern "C" {
    /// The extended `dlopen` function on Android that accepts an `AndroidDlextinfo` struct.
    pub fn android_dlopen_ext(
        filename: *const c_char,
        flags: libc::c_int,
        extinfo: *const AndroidDlextinfo,
    ) -> *mut c_void;
}

/// The function signature for `android_create_namespace`, which is not publicly exported
/// in headers but can be found via `dlsym`.
type AndroidCreateNamespaceFn = unsafe extern "C" fn(
    name: *const c_char,
    ld_library_path: *const c_char,
    default_library_path: *const c_char,
    type_: u64,
    permitted_when_isolated_path: *const c_char,
    parent: *mut AndroidNamespace,
    caller_addr: *const c_void,
) -> *mut AndroidNamespace;

/// A safe wrapper around `android_dlopen_ext` that creates a new linker namespace for the library.
///
/// This function dynamically looks up the `__loader_android_create_namespace` function,
/// creates a new shared namespace, and then uses `android_dlopen_ext` to load the
/// specified library into that namespace. This is crucial for isolating modules.
pub fn dlopen(path: &str, flags: i32) -> Result<*mut c_void> {
    let filename = CString::new(path)?;
    let filename_ptr = filename.as_ptr();

    // The library path for the new namespace should be the directory of the library itself.
    let mut path_bytes = filename.into_bytes_with_nul();
    let dir_ptr = unsafe { libc::dirname(path_bytes.as_mut_ptr() as *mut c_char) };

    let mut info = AndroidDlextinfo {
        flags: 0,
        reserved_addr: std::ptr::null_mut(),
        reserved_size: 0,
        relro_fd: 0,
        library_fd: 0,
        library_fd_offset: 0,
        library_namespace: std::ptr::null_mut(),
    };

    // Dynamically find the namespace creation function in the default linker context.
    let create_ns_fn_ptr = unsafe {
        let symbol_name = CString::new("__loader_android_create_namespace")?;
        libc::dlsym(libc::RTLD_DEFAULT, symbol_name.as_ptr())
    };

    if !create_ns_fn_ptr.is_null() {
        let android_create_namespace: AndroidCreateNamespaceFn =
            unsafe { std::mem::transmute(create_ns_fn_ptr) };

        // Create the namespace.
        let ns = unsafe {
            android_create_namespace(
                filename_ptr,
                dir_ptr,
                std::ptr::null(), // default_library_path
                ANDROID_NAMESPACE_TYPE_SHARED,
                std::ptr::null(),     // permitted_when_isolated_path
                std::ptr::null_mut(), // parent
                dlopen
                    as *const unsafe extern "C" fn(
                        *const c_char,
                        libc::c_int,
                        *const AndroidDlextinfo,
                    ) -> *mut c_void as *const c_void, // caller_addr
            )
        };

        if !ns.is_null() {
            info.flags = ANDROID_DLEXT_USE_NAMESPACE;
            info.library_namespace = ns;
            log::debug!("Opened {} with new linker namespace {:p}", path, ns);
        } else {
            log::warn!("Failed to create linker namespace for {}", path);
        }
    } else {
        log::warn!("Could not find __loader_android_create_namespace function.");
    }

    // Load the library using the extended info.
    let result = unsafe { android_dlopen_ext(filename_ptr, flags, &info) };
    if result.is_null() {
        let error_msg = unsafe { CStr::from_ptr(libc::dlerror()).to_string_lossy() };
        bail!("dlopen failed for {}: {}", path, error_msg);
    }

    Ok(result)
}
