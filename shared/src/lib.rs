use std::ops::Deref;
use std::path::PathBuf;

use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::Threading::*;
use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessId};
use windows::core::BOOL;
use windows::core::Owned;
use windows::core::PWSTR;
use windows::core::{s, w};

pub fn inject_dll(process: Process, hinstance: HINSTANCE) -> windows::core::Result<()> {
    let current_module = get_current_module_path(hinstance)?;
    let current_module_dir = current_module.parent().unwrap();

    let dll_path = if process.is_64_bit()? {
        current_module_dir.join("sandbox_hooks_64.dll")
    } else {
        current_module_dir.join("sandbox_hooks_32.dll")
    };

    println!("[INJECT] Injecting DLL: {}", dll_path.display());

    unsafe {
        let pid = GetProcessId(*process);
        let target_process = OpenProcess(PROCESS_ALL_ACCESS, false, pid)?;
        let target_process = Owned::new(target_process);

        let dll_path_wide = encode_wide(dll_path.to_str().unwrap());
        let dll_path_size = dll_path_wide.len() * std::mem::size_of::<u16>();

        let remote_mem = VirtualAllocEx(
            *target_process,
            None,
            dll_path_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_mem.is_null() {
            let err = GetLastError();
            println!("[INJECT] VirtualAllocEx failed: {:?}", err);
            return Err(E_FAIL.into());
        }

        // Ensure the allocated memory is freed if we exit early
        let _guard = ScopeGuard::new(|| {
            let _ = VirtualFreeEx(*target_process, remote_mem, 0, MEM_RELEASE);
        });

        let mut bytes_written = 0;
        if let Err(e) = WriteProcessMemory(
            *target_process,
            remote_mem,
            dll_path_wide.as_ptr() as *const _,
            dll_path_size,
            Some(&mut bytes_written),
        ) {
            println!("[INJECT] WriteProcessMemory failed: {:?}", e);
            return Err(E_FAIL.into());
        }

        let h_kernel32 = GetModuleHandleW(w!("kernel32.dll"))?;
        let load_library_addr = GetProcAddress(h_kernel32, s!("LoadLibraryW"));

        if let Some(load_library) = load_library_addr {
            let h_thread = CreateRemoteThread(
                *target_process,
                None,
                0,
                Some(std::mem::transmute(load_library)),
                Some(remote_mem),
                0,
                None,
            )?;
            let h_thread = Owned::new(h_thread);
            WaitForSingleObject(*h_thread, INFINITE);
        } else {
            let err = GetLastError();
            println!("[INJECT] GetProcAddress(LoadLibraryW) failed: {:?}", err);
            return Err(E_FAIL.into());
        }
    }

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
    pid: u32,
}

unsafe impl Send for Process {}
unsafe impl Sync for Process {}

impl Process {
    pub fn open(pid: u32) -> windows::core::Result<Process> {
        let process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid) }?;
        Ok(Process {
            handle: process,
            close_on_drop: true,
            pid,
        })
    }

    pub fn current() -> Process {
        let process = unsafe { GetCurrentProcess() };
        Process {
            handle: process,
            close_on_drop: false,
            pid: unsafe { GetProcessId(process) },
        }
    }

    pub fn from_raw_handle(handle: HANDLE) -> Process {
        Process {
            handle,
            close_on_drop: false,
            pid: unsafe { GetProcessId(handle) },
        }
    }

    pub fn raw_handle(&self) -> HANDLE {
        self.handle
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn is_64_bit(&self) -> windows::core::Result<bool> {
        unsafe {
            let mut is_wow64 = BOOL(0);
            IsWow64Process(self.handle, &mut is_wow64)?;
            Ok(is_wow64.as_bool() == false)
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

struct ScopeGuard<F: FnOnce()> {
    cleanup: Option<F>,
}

impl<F: FnOnce()> ScopeGuard<F> {
    fn new(cleanup: F) -> Self {
        Self {
            cleanup: Some(cleanup),
        }
    }
}

impl<F: FnOnce()> Drop for ScopeGuard<F> {
    fn drop(&mut self) {
        if let Some(cleanup) = self.cleanup.take() {
            cleanup();
        }
    }
}

pub fn encode_wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
