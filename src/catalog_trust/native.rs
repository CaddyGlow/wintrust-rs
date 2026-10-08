use super::*;
use std::{
    ffi::c_void,
    fs::File,
    os::windows::{ffi::OsStrExt, io::AsRawHandle},
    ptr,
};

type Handle = *mut c_void;
#[repr(C)]
struct Guid {
    a: u32,
    b: u16,
    c: u16,
    d: [u8; 8],
}
// WINTRUST_ACTION_GENERIC_VERIFY_V2, SDK wintrust.h.
const ACTION: Guid = Guid {
    a: 0x00aac56b,
    b: 0xcd44,
    c: 0x11d0,
    d: [0x8c, 0xc2, 0, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
};
#[repr(C)]
struct CatalogInfo {
    size: u32,
    version: u32,
    catalog: *const u16,
    tag: *const u16,
    member: *const u16,
    file: Handle,
    hash: *mut u8,
    hash_len: u32,
    context: Handle,
    admin: Handle,
}
#[repr(C)]
struct TrustData {
    size: u32,
    policy: Handle,
    sip: Handle,
    ui: u32,
    revocation: u32,
    choice: u32,
    catalog: *mut CatalogInfo,
    action: u32,
    state: Handle,
    url: *const u16,
    flags: u32,
    ui_context: u32,
    settings: Handle,
}
type Acquire = unsafe extern "system" fn(*mut Handle, *const Guid, *const u16, Handle, u32) -> i32;
type Hash = unsafe extern "system" fn(Handle, Handle, *mut u32, *mut u8, u32) -> i32;
type Release = unsafe extern "system" fn(Handle, u32) -> i32;
type Verify = unsafe extern "system" fn(Handle, *const Guid, *mut TrustData) -> i32;
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryExW(name: *const u16, file: Handle, flags: u32) -> Handle;
    fn GetProcAddress(module: Handle, name: *const u8) -> Handle;
    fn FreeLibrary(module: Handle) -> i32;
    fn GetLastError() -> u32;
}
struct Module(Handle);
impl Drop for Module {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.0);
        }
    }
}
struct Admin {
    handle: Handle,
    release: Release,
}
impl Drop for Admin {
    fn drop(&mut self) {
        unsafe {
            (self.release)(self.handle, 0);
        }
    }
}
struct State {
    data: TrustData,
    verify: Verify,
}
impl Drop for State {
    fn drop(&mut self) {
        self.data.action = 2; // Every VERIFY call is paired with CLOSE, including failures.
        unsafe {
            (self.verify)(ptr::null_mut(), &ACTION, &mut self.data);
        }
    }
}
fn win_error(operation: &'static str) -> TrustError {
    TrustError::WindowsApi {
        operation,
        code: unsafe { GetLastError() },
    }
}
fn wide(path: &Path) -> Result<Vec<u16>, TrustError> {
    let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
    if value.contains(&0) {
        return Err(TrustError::InvalidInput("path contains NUL".into()));
    }
    value.push(0);
    Ok(value)
}
fn export(module: Handle, name: &std::ffi::CStr) -> Result<Handle, TrustError> {
    let address = unsafe { GetProcAddress(module, name.as_ptr().cast()) };
    if address.is_null() {
        Err(win_error("GetProcAddress"))
    } else {
        Ok(address)
    }
}

pub(super) fn verify(
    catalog: &Path,
    member: &Path,
    options: TrustOptions,
) -> Result<TrustReport, TrustError> {
    // Keep read handles open without write/delete sharing during verification.
    use std::os::windows::fs::OpenOptionsExt;
    let catalog = std::fs::canonicalize(catalog)?;
    let member = std::fs::canonicalize(member)?;
    let mut catalog_file = File::options().read(true).share_mode(1).open(&catalog)?;
    let mut member_file = File::options().read(true).share_mode(1).open(&member)?;
    let catalog_sha256 = raw_hash(&mut catalog_file)?;
    let member_sha256 = raw_hash(&mut member_file)?;
    let catalog_name = wide(&catalog)?;
    let member_name = wide(&member)?;
    let library: Vec<u16> = "wintrust.dll\0".encode_utf16().collect();
    // LOAD_LIBRARY_SEARCH_SYSTEM32 prevents working-directory DLL substitution.
    let handle = unsafe { LoadLibraryExW(library.as_ptr(), ptr::null_mut(), 0x800) };
    if handle.is_null() {
        return Err(win_error("LoadLibraryExW(wintrust.dll)"));
    }
    let _module = Module(handle);
    // Named exports use the exact documented SDK signatures; _module outlives calls.
    let acquire: Acquire =
        unsafe { std::mem::transmute(export(handle, c"CryptCATAdminAcquireContext2")?) };
    let hash: Hash =
        unsafe { std::mem::transmute(export(handle, c"CryptCATAdminCalcHashFromFileHandle2")?) };
    let release: Release =
        unsafe { std::mem::transmute(export(handle, c"CryptCATAdminReleaseContext")?) };
    let verify: Verify = unsafe { std::mem::transmute(export(handle, c"WinVerifyTrust")?) };
    let algorithm: Vec<u16> = match options.hash_algorithm {
        CatalogHashAlgorithm::Sha256 => "SHA256\0",
        CatalogHashAlgorithm::Sha1 => "SHA1\0",
    }
    .encode_utf16()
    .collect();
    let mut admin = ptr::null_mut();
    if unsafe {
        acquire(
            &mut admin,
            ptr::null(),
            algorithm.as_ptr(),
            ptr::null_mut(),
            0,
        )
    } == 0
    {
        return Err(win_error("CryptCATAdminAcquireContext2"));
    }
    let admin = Admin {
        handle: admin,
        release,
    };
    let mut length = 0;
    if unsafe {
        hash(
            admin.handle,
            member_file.as_raw_handle(),
            &mut length,
            ptr::null_mut(),
            0,
        )
    } == 0
    {
        return Err(win_error("CryptCATAdminCalcHashFromFileHandle2(size)"));
    }
    let expected = match options.hash_algorithm {
        CatalogHashAlgorithm::Sha256 => 32,
        CatalogHashAlgorithm::Sha1 => 20,
    };
    if length != expected {
        return Err(TrustError::InvalidInput(
            "unexpected native catalog hash length".into(),
        ));
    }
    let mut digest = vec![0; length as usize];
    if unsafe {
        hash(
            admin.handle,
            member_file.as_raw_handle(),
            &mut length,
            digest.as_mut_ptr(),
            0,
        )
    } == 0
    {
        return Err(win_error("CryptCATAdminCalcHashFromFileHandle2"));
    }
    if length != expected {
        return Err(TrustError::InvalidInput(
            "native catalog hash length changed".into(),
        ));
    }
    let hash_hex = hex::encode(&digest);
    let tag: Vec<u16> = format!("{}\0", hash_hex.to_ascii_uppercase())
        .encode_utf16()
        .collect();
    let mut info = CatalogInfo {
        size: std::mem::size_of::<CatalogInfo>() as u32,
        version: 0,
        catalog: catalog_name.as_ptr(),
        tag: tag.as_ptr(),
        member: member_name.as_ptr(),
        file: member_file.as_raw_handle(),
        hash: digest.as_mut_ptr(),
        hash_len: length,
        context: ptr::null_mut(),
        admin: admin.handle,
    };
    let (revocation, flags) = match options.revocation {
        RevocationPolicy::CacheOnly => (1, 0x80 | 0x1000 | 0x2000),
        RevocationPolicy::Online => (1, 0x80 | 0x2000),
        RevocationPolicy::Disabled => (0, 0x10 | 0x1000 | 0x2000),
    };
    let mut state = State {
        verify,
        data: TrustData {
            size: std::mem::size_of::<TrustData>() as u32,
            policy: ptr::null_mut(),
            sip: ptr::null_mut(),
            ui: 2,
            revocation,
            choice: 2,
            catalog: &mut info,
            action: 1,
            state: ptr::null_mut(),
            url: ptr::null(),
            flags,
            ui_context: 0,
            settings: ptr::null_mut(),
        },
    };
    // All buffers, handles and SDK-layout structures remain live through CLOSE.
    let status = unsafe { verify(ptr::null_mut(), &ACTION, &mut state.data) } as u32;
    drop(state);
    if raw_hash(&mut catalog_file)? != catalog_sha256
        || raw_hash(&mut member_file)? != member_sha256
    {
        return Err(TrustError::InvalidInput(
            "catalog or member changed during verification".into(),
        ));
    }
    Ok(TrustReport {
        backend: "windows_winverifytrust_catalog".into(),
        status: if status == 0 {
            TrustStatus::WindowsAuthenticodeTrusted
        } else {
            TrustStatus::Rejected
        },
        winverifytrust_status: status,
        member_hash: hash_hex,
        catalog_path: catalog,
        member_path: member,
        catalog_sha256,
        member_sha256,
        options,
        microsoft_signer_verified: false,
    })
}

fn raw_hash(file: &mut File) -> Result<String, TrustError> {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(hex::encode(digest.finalize()))
}
