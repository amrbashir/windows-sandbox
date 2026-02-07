use std::ffi::OsStr;
use std::ffi::OsString;
use std::ops::Deref;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use windows::core::PWSTR;
use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Win32::Foundation::*;
use windows::Win32::Storage::FileSystem::{GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED};
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Threading::*;

pub const PROTECTED_PATH: &str = r"test\secret.txt";

pub fn is_protected_path(path: &str) -> bool {
    path.ends_with(PROTECTED_PATH)
}

pub fn check_and_deny(path: &str, api_name: &str) -> bool {
    if is_protected_path(path) {
        eprintln!("[HOOK:{}] Denying access to {}", api_name, path);
        return true;
    }
    false
}

pub fn get_path_from_handle(handle: HANDLE) -> String {
    let mut buf = [0u16; MAX_PATH as _];
    let result = unsafe { GetFinalPathNameByHandleW(handle, &mut buf, FILE_NAME_NORMALIZED) };
    if result == 0 {
        // Not a file handle or error - return empty string
        return String::new();
    }
    decode_wide(&buf).to_string_lossy().into()
}

pub fn get_path_from_object_attrs(obj_attr: *mut OBJECT_ATTRIBUTES) -> String {
    let mut buf = [0u16; MAX_PATH as _];
    unsafe {
        if !obj_attr.is_null() && !(*obj_attr).ObjectName.is_null() {
            let name = &*(*obj_attr).ObjectName;
            let len = (name.Length / 2) as usize;
            if len > 0 && len < MAX_PATH as usize {
                std::slice::from_raw_parts(name.Buffer.as_ptr(), len)
                    .iter()
                    .enumerate()
                    .for_each(|(i, &c)| buf[i] = c);
            }
        }
    }
    decode_wide(&buf).to_string_lossy().into()
}

pub fn inject_dll(process: Process, hinstance: HINSTANCE) -> windows::core::Result<()> {
    let current_module = get_current_module_path(hinstance)?;
    let current_module_dir = current_module.parent().unwrap();

    let dll_path_32 = current_module_dir.join("sandbox_hooks_32.dll");
    let dll_path_64 = current_module_dir.join("sandbox_hooks_64.dll");

    let dll_path_32 = encode_wide(dll_path_32);
    let dll_path_64 = encode_wide(dll_path_64);

    unsafe { dllinject::InjectDll((*process).0, dll_path_32.as_ptr(), dll_path_64.as_ptr()) };

    Ok(())
}

#[unsafe(no_mangle)]
fn get_current_module_path(hinstance: HINSTANCE) -> windows::core::Result<PathBuf> {
    unsafe {
        let mut path_buf = vec![0u16; 260];
        GetModuleFileNameW(Some(HMODULE(hinstance.0)), &mut path_buf);

        let path = String::from_utf16_lossy(&path_buf);
        Ok(PathBuf::from(path))
    }
}

pub struct Process {
    handle: HANDLE,
    close_on_drop: bool,
}

unsafe impl Send for Process {}
unsafe impl Sync for Process {}

impl Process {
    pub fn open(pid: u32) -> windows::core::Result<Process> {
        let process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid) }?;
        let process = Process {
            handle: process,
            close_on_drop: true,
        };
        Ok(process)
    }

    pub fn from_raw_handle(handle: HANDLE) -> Process {
        Process {
            handle,
            close_on_drop: false,
        }
    }

    pub fn exe_path(&self) -> windows::core::Result<String> {
        let mut buf = vec![0u16; 260];
        let mut size = buf.len() as u32;

        unsafe {
            QueryFullProcessImageNameW(
                self.handle,
                PROCESS_NAME_WIN32,
                PWSTR(buf.as_mut_ptr()),
                &mut size,
            )
        }?;

        let path = String::from_utf16_lossy(&buf[..size as usize]);
        Ok(path)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.close_on_drop {
            let _ = unsafe { CloseHandle(self.handle) };
        }
    }
}

impl Deref for Process {
    type Target = HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
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
