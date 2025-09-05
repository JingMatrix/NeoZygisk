mod apatch;
mod kernelsu;
mod magisk;

#[derive(Debug)]
pub enum RootImpl {
    None,
    TooOld,
    Multiple,
    APatch,
    KernelSU,
    Magisk,
}

static mut ROOT_IMPL: RootImpl = RootImpl::None;

pub fn setup() {
    let apatch_version = apatch::get_apatch();
    let ksu_version = kernelsu::get_kernel_su();
    let magisk_version = magisk::get_magisk();

    let impl_ = match (apatch_version, ksu_version, magisk_version) {
        (None, None, None) => RootImpl::None,
        (None, Some(_), Some(_)) => RootImpl::Multiple,
        (Some(_), None, Some(_)) => RootImpl::Multiple,
        (Some(_), Some(_), None) => RootImpl::Multiple,
        (Some(_), Some(_), Some(_)) => RootImpl::Multiple,
        (Some(apatch_version), None, None) => match apatch_version {
            apatch::Version::Supported => RootImpl::APatch,
            apatch::Version::TooOld => RootImpl::TooOld,
        },
        (None, Some(ksu_version), None) => match ksu_version {
            kernelsu::Version::Supported => RootImpl::KernelSU,
            kernelsu::Version::TooOld => RootImpl::TooOld,
        },
        (None, None, Some(magisk_version)) => match magisk_version {
            magisk::Version::Supported => RootImpl::Magisk,
            magisk::Version::TooOld => RootImpl::TooOld,
        },
    };
    unsafe {
        ROOT_IMPL = impl_;
    }
}

pub fn get_impl() -> &'static RootImpl {
    unsafe { &*(&raw const ROOT_IMPL) }
}

pub fn uid_granted_root(uid: i32) -> bool {
    match get_impl() {
        RootImpl::APatch => apatch::uid_granted_root(uid),
        RootImpl::KernelSU => kernelsu::uid_granted_root(uid),
        RootImpl::Magisk => magisk::uid_granted_root(uid),
        _ => panic!("uid_granted_root: unknown root impl {:?}", get_impl()),
    }
}

pub fn uid_should_umount(uid: i32) -> bool {
    match get_impl() {
        RootImpl::APatch => apatch::uid_should_umount(uid),
        RootImpl::KernelSU => kernelsu::uid_should_umount(uid),
        RootImpl::Magisk => magisk::uid_should_umount(uid),
        _ => panic!("uid_should_umount: unknown root impl {:?}", get_impl()),
    }
}

pub fn uid_is_manager(uid: i32) -> bool {
    match get_impl() {
        RootImpl::APatch => apatch::uid_is_manager(uid),
        RootImpl::KernelSU => kernelsu::uid_is_manager(uid),
        RootImpl::Magisk => magisk::uid_is_manager(uid),
        _ => panic!("uid_is_manager: unknown root impl {:?}", get_impl()),
    }
}
