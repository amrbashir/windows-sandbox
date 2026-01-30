use std::ops::Deref;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::ClientOptions;

use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::Threading::*;
use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessId};
use windows::core::BOOL;
use windows::core::PWSTR;
use windows::core::{s, w};

pub fn inject_dll_into_process(target: Process) -> windows::core::Result<()> {
    let host = Process::current();
    let is_host_64_bit = host.is_64_bit()?;
    let is_target_64_bit = target.is_64_bit()?;

    println!(
        "[INJECT] Host 64-bit: {}, Target 64-bit: {}",
        is_host_64_bit, is_target_64_bit
    );

    if is_host_64_bit == is_target_64_bit {
        inject_dll(*target, is_target_64_bit)?;
    } else {
        println!("[INJECT] Using pipe for cross-bitness injection");
        inject_via_pipe(target.pid())?;
    }

    Ok(())
}

pub async fn inject_dll_into_process_async(target: Process) -> windows::core::Result<()> {
    let host = Process::current();
    let is_host_64_bit = host.is_64_bit()?;
    let is_target_64_bit = target.is_64_bit()?;

    println!(
        "[INJECT] Host 64-bit: {}, Target 64-bit: {}",
        is_host_64_bit, is_target_64_bit
    );

    if is_host_64_bit == is_target_64_bit {
        inject_dll(*target, is_target_64_bit)?;
    } else {
        println!("[INJECT] Using pipe for cross-bitness injection");
        inject_via_pipe_async(target.pid()).await?;
    }

    Ok(())
}

pub const PIPE_NAME: &str = r"\\.\pipe\sandbox_inject";

fn inject_via_pipe(pid: u32) -> std::io::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async { inject_via_pipe_async(pid).await })
}

async fn inject_via_pipe_async(pid: u32) -> std::io::Result<()> {
    println!("[PIPE] Connecting to pipe for PID {pid}",);
    let mut client = ClientOptions::new().open(PIPE_NAME)?;

    println!("[PIPE] Sending inject request for PID {pid}");
    let pid_bytes = pid.to_le_bytes();
    client.write_all(&pid_bytes).await.map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Pipe write failed: {}", e),
        )
    })?;
    client.flush().await.map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Pipe flush failed: {}", e),
        )
    })?;

    println!("[PIPE] Waiting for response");
    let mut resp = [0u8; 1];
    client.read_exact(&mut resp).await.map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Pipe read failed: {}", e),
        )
    })?;

    if resp[0] != 0 {
        let err = format!("Injection failed with status code {}", resp[0]);
        return Err(std::io::Error::other(err));
    }
    println!("[PIPE] Injection completed successfully");

    Ok(())
}

pub fn inject_dll(process: HANDLE, is_64_bit: bool) -> windows::core::Result<()> {
    let current_exe = std::env::current_exe()?;
    let current_exe_dir = current_exe.parent().unwrap();

    let dll_path = if is_64_bit {
        current_exe_dir.join("sandbox_hooks_64.dll")
    } else {
        current_exe_dir.join("sandbox_hooks_32.dll")
    };

    println!("[INJECT] Current exe: {}", current_exe.display());
    println!("[INJECT] DLL path: {}", dll_path.display());
    println!("[INJECT] DLL exists: {}", dll_path.exists());

    if !dll_path.exists() {
        println!("[INJECT] DLL not found!");
        return Err(E_FAIL.into());
    }

    unsafe {
        let dll_path_wide = encode_wide(dll_path.to_str().unwrap());
        let dll_path_size = dll_path_wide.len() * std::mem::size_of::<u16>();

        let bitness = if is_64_bit { "64-bit" } else { "32-bit" };
        println!("[INJECT] Injecting DLL ({bitness}): {}", dll_path.display());

        let remote_mem = VirtualAllocEx(
            process,
            None,
            dll_path_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_mem.is_null() {
            println!("[INJECT] Failed to allocate memory in target process");
            return Err(E_FAIL.into());
        }

        println!("[INJECT] Allocated memory at {remote_mem:?}");

        let mut bytes_written = 0;
        WriteProcessMemory(
            process,
            remote_mem,
            dll_path_wide.as_ptr() as *const _,
            dll_path_size,
            Some(&mut bytes_written),
        )?;

        let h_kernel32 = GetModuleHandleW(w!("kernel32.dll"))?;
        let load_library_addr = GetProcAddress(h_kernel32, s!("LoadLibraryW"));

        if let Some(load_library) = load_library_addr {
            println!("[INJECT] Loading the DLL via LoadLibraryW in remote process");
            let h_thread = CreateRemoteThread(
                process,
                None,
                0,
                Some(std::mem::transmute(load_library)),
                Some(remote_mem),
                0,
                None,
            )?;

            println!("[INJECT] Waiting for LoadLibraryW to complete");
            WaitForSingleObject(h_thread, INFINITE);

            println!("[INJECT] DLL injected successfully");
            CloseHandle(h_thread)?;
        } else {
            VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE)?;
            return Err(E_FAIL.into());
        }

        VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE)?;
    }

    Ok(())
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

pub fn encode_wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
