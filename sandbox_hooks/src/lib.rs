#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

use minhook_detours::*;
use std::ffi::c_void;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::Foundation::NTSTATUS;
use windows::Win32::Foundation::STATUS_ACCESS_DENIED;
use windows::Win32::Storage::FileSystem::FILE_NAME_NORMALIZED;
use windows::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::Win32::System::IO::PIO_APC_ROUTINE;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::LibraryLoader::GetProcAddress;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::System::SystemServices::DLL_PROCESS_DETACH;
use windows::Win32::System::Threading::CREATE_SUSPENDED;
use windows::Win32::System::Threading::TerminateProcess;
use windows::Win32::System::Threading::{PROCESS_INFORMATION, ResumeThread, STARTUPINFOW};
use windows::core::BOOL;
use windows::core::{s, w};

type NTREADFILE = extern "system" fn(
    filehandle: HANDLE,
    event: HANDLE,
    apcroutine: PIO_APC_ROUTINE,
    apccontext: *const c_void,
    iostatusblock: *mut IO_STATUS_BLOCK,
    buffer: *mut c_void,
    length: u32,
    byteoffset: *const i64,
    key: *const u32,
) -> NTSTATUS;

type CREATEPROCESSINTERNALW = extern "system" fn(
    HANDLE,
    *const u16,
    *mut u16,
    *mut c_void,
    *mut c_void,
    BOOL,
    u32,
    *mut c_void,
    *const u16,
    *mut STARTUPINFOW,
    *mut PROCESS_INFORMATION,
    *mut c_void,
) -> BOOL;

static mut pOriginalNtReadFile: NTREADFILE = NtReadFile_tour;

extern "system" fn NtReadFile_tour(
    filehandle: HANDLE,
    event: HANDLE,
    apcroutine: PIO_APC_ROUTINE,
    apccontext: *const c_void,
    iostatusblock: *mut IO_STATUS_BLOCK,
    buffer: *mut c_void,
    length: u32,
    byteoffset: *const i64,
    key: *const u32,
) -> NTSTATUS {
    let mut file_name_buf = [0u16; 260];
    unsafe { GetFinalPathNameByHandleW(filehandle, &mut file_name_buf, FILE_NAME_NORMALIZED) };

    let file_name = String::from_utf16_lossy(
        &file_name_buf
            .iter()
            .take_while(|&&c| c != 0)
            .cloned()
            .collect::<Vec<u16>>(),
    );

    // Deny access to test\secret.txt
    if file_name.ends_with(r"test\secret.txt") {
        eprintln!("[HOOK:NtReadFile] Denying access to {file_name}");
        return STATUS_ACCESS_DENIED;
    }

    // Call the original NtReadFile
    let res = unsafe {
        pOriginalNtReadFile(
            filehandle,
            event,
            apcroutine,
            apccontext,
            iostatusblock,
            buffer,
            length,
            byteoffset,
            key,
        )
    };
    res
}

static mut pOriginalCreateProcessInternalW: CREATEPROCESSINTERNALW = CreateProcessInternalW_tour;

#[allow(non_snake_case)]
extern "system" fn CreateProcessInternalW_tour(
    hToken: HANDLE,
    applicationName: *const u16,
    commandLine: *mut u16,
    processAttributes: *mut c_void,
    threadAttributes: *mut c_void,
    inheritHandles: BOOL,
    creationFlags: u32,
    environment: *mut c_void,
    currentDirectory: *const u16,
    startupInfo: *mut STARTUPINFOW,
    processInformation: *mut PROCESS_INFORMATION,
    restrictedUserToken: *mut c_void,
) -> BOOL {
    eprintln!("[HOOK:CreateProcessInternalW] intercepted");

    // Call the original CreateProcessInternalW
    let result = unsafe {
        pOriginalCreateProcessInternalW(
            hToken,
            applicationName,
            commandLine,
            processAttributes,
            threadAttributes,
            inheritHandles,
            creationFlags | CREATE_SUSPENDED.0,
            environment,
            currentDirectory,
            startupInfo,
            processInformation,
            restrictedUserToken,
        )
    };

    // If process created successfully, inject hooks into the new process, then resume thread
    if result.as_bool() && !processInformation.is_null() {
        let pi = unsafe { &*processInformation };
        let hprocess = pi.hProcess;
        let thread = pi.hThread;

        let process = shared::Process::from_raw_handle(hprocess);
        let exe_path = process.exe_path().unwrap_or_default();

        eprintln!("[HOOK:CreateProcessInternalW] Injecting hooks into child process:  {exe_path}");
        if let Err(e) = shared::inject_dll(process, unsafe { G_HINST_DLL }) {
            eprintln!("[HOOK:CreateProcessInternalW] Failed to inject into child process: {e:?}");
            let _ = unsafe { TerminateProcess(hprocess, 1) };
            return BOOL(0);
        }

        // Resume the main thread if it wasn't created suspended
        if creationFlags & CREATE_SUSPENDED.0 == 0 {
            unsafe { ResumeThread(thread) };
        }
    }

    result
}

macro_rules! install_hook {
    ($h_ntdll:expr, $fn_name:literal, $original:ident, $hook:expr) => {
        if let Some(target) = GetProcAddress($h_ntdll, s!($fn_name)) {
            let mut temp_orig: *mut c_void = std::ptr::null_mut();
            if MH_CreateHook(target as *mut c_void, $hook as *mut c_void, &mut temp_orig) != MH_OK {
                eprintln!("[INIT] ERROR: Failed to create {} hook", $fn_name);
                return;
            }

            if MH_EnableHook(target as *mut c_void) != MH_OK {
                eprintln!("[INIT] ERROR: Failed to enable {} hook", $fn_name);
                return;
            }

            $original = std::mem::transmute(temp_orig);

            eprintln!("[INIT] {} hook installed", $fn_name);
        } else {
            eprintln!("[INIT] WARNING: {} not found", $fn_name);
        }
    };
}

fn uninit_hooks() {
    eprintln!("[UNINIT] Uninitializing sandbox hooks...");

    unsafe {
        if MH_Uninitialize() != MH_OK {
            eprintln!("[UNINIT] WARNING: MinHook uninitialization failed");
            return;
        }
    }

    eprintln!("[UNINIT] Sandbox hooks uninitialized successfully");
}

fn init_hooks() {
    eprintln!("[INIT] Initializing sandbox hooks...");

    unsafe {
        if MH_Initialize() != MH_OK {
            eprintln!("[INIT] Failed to initialize MinHook");
            return;
        }

        let h_ntdll = GetModuleHandleW(w!("ntdll.dll")).unwrap();
        let h_kernelbase = GetModuleHandleW(w!("kernelbase.dll")).unwrap();

        install_hook!(h_ntdll, "NtReadFile", pOriginalNtReadFile, NtReadFile_tour);

        install_hook!(
            h_kernelbase,
            "CreateProcessInternalW",
            pOriginalCreateProcessInternalW,
            CreateProcessInternalW_tour
        );
    }

    eprintln!("[INIT] All hooks initialized successfully");
}

static mut G_HINST_DLL: HINSTANCE = HINSTANCE(0 as _);

#[unsafe(no_mangle)]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(hinstDLL: HINSTANCE, fdw_reason: u32, _lpv_reserved: *mut ()) -> bool {
    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            unsafe { G_HINST_DLL = hinstDLL };
            init_hooks()
        }
        DLL_PROCESS_DETACH => uninit_hooks(),
        _ => (),
    }

    true
}
