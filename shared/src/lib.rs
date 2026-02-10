use anyhow::{Context, Result};
use std::ffi::OsStr;
use std::ffi::OsString;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::OnceLock;

use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Win32::Foundation::*;
use windows::Win32::Storage::FileSystem::{FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW};
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Memory::*;
use windows::core::PCWSTR;

const SANDBOX_MMF_PREFIX: &str = "Local\\SandboxDenyConfig";

#[derive(Debug, Clone, wincode::SchemaWrite, wincode::SchemaRead)]
pub struct DenyConfig {
    pub paths: Vec<String>,
}

static DENY_CONFIG: OnceLock<DenyConfig> = OnceLock::new();

pub fn init_deny_config() {
    let Ok(config) = read_deny_config() else {
        return;
    };

    let _ = DENY_CONFIG.set(config);
}

pub fn get_denied_paths() -> &'static [String] {
    &DENY_CONFIG
        .get()
        .expect("Deny config not initialized, call init_deny_config() first")
        .paths
}

pub fn is_path_denied(path: &str) -> bool {
    let deny = get_denied_paths();
    deny.iter().any(|denied| denied == path)
}

pub fn create_deny_config(pid: u32, paths: &[PathBuf]) -> Result<HANDLE> {
    // Convert PathBuf slice to String vector for serialization
    let config = DenyConfig {
        paths: paths
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect(),
    };

    // Serialize data
    let bytes = wincode::serialize(&config).context("Failed to serialize deny config")?;

    let data_bytes = bytes.len();
    let total_size = 8 + data_bytes; // 8 bytes for length prefix + data

    // Create shared memory file mapping with unique name based on child PID
    let name = encode_wide(format!("{SANDBOX_MMF_PREFIX}_{pid}"));
    let mapping = unsafe {
        CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            None,
            PAGE_READWRITE,
            0,
            total_size as u32,
            PCWSTR(name.as_ptr()),
        )?
    };

    // Create a writeable view to copy data into
    let view = unsafe { MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, 0) };
    if view.Value.is_null() {
        unsafe { CloseHandle(mapping).ok() };
        anyhow::bail!("Failed to map view of file");
    }

    unsafe {
        // Write 8-byte length prefix (u64)
        let len_prefix = data_bytes as u64;
        let len_bytes = len_prefix.to_le_bytes();
        std::ptr::copy_nonoverlapping(len_bytes.as_ptr(), view.Value as *mut u8, 8);

        // Write data at offset 8
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), (view.Value as *mut u8).add(8), data_bytes);

        // Unmap view but keep handle open so memory stays valid for child process
        let _ = UnmapViewOfFile(view);
    }

    Ok(mapping)
}

fn read_deny_config() -> Result<DenyConfig> {
    // Open the shared memory mapping for this process's PID
    let name = encode_wide(format!("{SANDBOX_MMF_PREFIX}_{}", std::process::id()));
    let mapping = unsafe { OpenFileMappingW(FILE_MAP_READ.0, false, PCWSTR(name.as_ptr()))? };

    // Create a read-only view to access the data
    let view = unsafe { MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0) };
    if view.Value.is_null() {
        unsafe { CloseHandle(mapping).ok() };
        anyhow::bail!("Failed to map view of file");
    }

    unsafe {
        // Read 8-byte length prefix
        let mut len_bytes = [0u8; 8];
        std::ptr::copy_nonoverlapping(view.Value as *const u8, len_bytes.as_mut_ptr(), 8);
        let data_len = u64::from_le_bytes(len_bytes) as usize;

        // Get pointer to data at offset 8
        let data_ptr = (view.Value as *const u8).add(8);

        // Create a slice of the data
        let data_slice = std::slice::from_raw_parts(data_ptr, data_len);

        // Deserialize config
        let deny = wincode::deserialize(data_slice).context("Failed to deserialize deny config")?;

        let _ = UnmapViewOfFile(view);
        let _ = CloseHandle(mapping);

        Ok(deny)
    }
}

pub fn inject_dll(hprocess: HANDLE, hinstance: HINSTANCE) -> Result<()> {
    let current_module = get_current_module_path(hinstance)?;
    let current_module_dir = current_module
        .parent()
        .context("Failed to get parent directory of current module")?;

    let dll_path_32 = current_module_dir.join("sandbox_hooks_32.dll");
    let dll_path_64 = current_module_dir.join("sandbox_hooks_64.dll");

    let dll_path_32 = encode_wide(dll_path_32);
    let dll_path_64 = encode_wide(dll_path_64);

    let result =
        unsafe { dllinject::InjectDll(hprocess.0, dll_path_32.as_ptr(), dll_path_64.as_ptr()) };
    if result != 0 {
        anyhow::bail!("DLL injection failed with error code: {result}");
    }

    Ok(())
}

fn get_current_module_path(hinstance: HINSTANCE) -> Result<PathBuf> {
    let mut buf = vec![0u16; MAX_PATH as usize];

    let result = unsafe { GetModuleFileNameW(Some(HMODULE(hinstance.0)), &mut buf) };
    if result == 0 {
        anyhow::bail!("Failed to get module file name");
    }

    let path = String::from_utf16_lossy(&buf);
    Ok(PathBuf::from(path))
}

pub fn get_path_from_handle(handle: HANDLE) -> String {
    let mut buf = [0u16; MAX_PATH as _];

    let result = unsafe { GetFinalPathNameByHandleW(handle, &mut buf, FILE_NAME_NORMALIZED) };
    if result == 0 {
        return String::new();
    }

    decode_wide(&buf).to_string_lossy().into_owned()
}

pub fn get_path_from_object_attrs(obj_attr: *mut OBJECT_ATTRIBUTES) -> String {
    if obj_attr.is_null() || unsafe { (*obj_attr).ObjectName.is_null() } {
        return String::new();
    }

    let mut buf = [0u16; MAX_PATH as _];

    let name = unsafe { &*(*obj_attr).ObjectName };
    let len = (name.Length / 2) as usize;
    if len <= 0 || len > MAX_PATH as usize {
        return String::new();
    }

    unsafe { std::ptr::copy_nonoverlapping(name.Buffer.0, buf.as_mut_ptr(), len) };

    decode_wide(&buf).to_string_lossy().into_owned()
}

pub fn encode_wide(string: impl AsRef<OsStr>) -> Vec<u16> {
    use std::iter::once;

    string.as_ref().encode_wide().chain(once(0)).collect()
}

pub fn decode_wide(mut wide_c_string: &[u16]) -> OsString {
    if let Some(null_pos) = wide_c_string.iter().position(|c| *c == 0) {
        wide_c_string = &wide_c_string[..null_pos];
    }

    OsString::from_wide(wide_c_string)
}
