#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

use anyhow::{Context, Result};
use minhook_detours::*;
use std::ffi::c_void;
use std::path::PathBuf;
use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Wdk::Storage::FileSystem::FILE_BASIC_INFORMATION;
use windows::Wdk::Storage::FileSystem::FILE_NETWORK_OPEN_INFORMATION;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::Foundation::NTSTATUS;
use windows::Win32::Foundation::STATUS_ACCESS_DENIED;
use windows::Win32::Foundation::UNICODE_STRING;
use windows::Win32::Storage::FileSystem::FILE_SEGMENT_ELEMENT;
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::Win32::System::IO::PIO_APC_ROUTINE;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::LibraryLoader::GetProcAddress;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::System::SystemServices::DLL_PROCESS_DETACH;
use windows::Win32::System::Threading::CREATE_SUSPENDED;
use windows::Win32::System::Threading::GetProcessId;
use windows::Win32::System::Threading::TerminateProcess;
use windows::Win32::System::Threading::{PROCESS_INFORMATION, ResumeThread, STARTUPINFOW};
use windows::core::BOOL;
use windows::core::{s, w};

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

// --- Process Creation ---
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

// --- File Creation & Opening ---
type NTCREATEFILE = extern "system" fn(
    filehandle: *mut HANDLE,
    desiredaccess: u32,
    objectattributes: *mut OBJECT_ATTRIBUTES,
    iostatusblock: *mut IO_STATUS_BLOCK,
    allocationsize: *const i64,
    fileattributes: u32,
    shareaccess: u32,
    createDisposition: u32,
    createoptions: u32,
    eabuffer: *const c_void,
    ealength: u32,
) -> NTSTATUS;

type NTOPENFILE = extern "system" fn(
    filehandle: *mut HANDLE,
    desiredaccess: u32,
    objectattributes: *mut OBJECT_ATTRIBUTES,
    iostatusblock: *mut IO_STATUS_BLOCK,
    shareaccess: u32,
    openoptions: u32,
) -> NTSTATUS;

// --- Symbolic Link Operations ---
type NTCREATESYMBOLICLINKOBJECT = extern "system" fn(
    linkhandle: *mut HANDLE,
    desiredaccess: u32,
    objectattributes: *mut OBJECT_ATTRIBUTES,
    linktarget: *const UNICODE_STRING,
) -> NTSTATUS;

type NTOPENSYMBOLICLINKOBJECT = extern "system" fn(
    linkhandle: *mut HANDLE,
    desiredaccess: u32,
    objectattributes: *mut OBJECT_ATTRIBUTES,
) -> NTSTATUS;

type NTQUERYSYMBOLICLINKOBJECT = extern "system" fn(
    linkhandle: HANDLE,
    linktarget: *mut UNICODE_STRING,
    returnedlength: *mut u32,
) -> NTSTATUS;

// --- File Reading ---
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

type NTREADFILESCATTER = extern "system" fn(
    filehandle: HANDLE,
    event: HANDLE,
    apcroutine: PIO_APC_ROUTINE,
    apccontext: *const c_void,
    iostatusblock: *mut IO_STATUS_BLOCK,
    segmentarray: *const FILE_SEGMENT_ELEMENT,
    length: u32,
    byteoffset: *const i64,
    key: *const u32,
) -> NTSTATUS;

// --- File Writing ---
type NTWRITEFILE = extern "system" fn(
    filehandle: HANDLE,
    event: HANDLE,
    apcroutine: PIO_APC_ROUTINE,
    apccontext: *const c_void,
    iostatusblock: *mut IO_STATUS_BLOCK,
    buffer: *const c_void,
    length: u32,
    byteoffset: *const i64,
    key: *const u32,
) -> NTSTATUS;

type NTWRITEFILEGATHER = extern "system" fn(
    filehandle: HANDLE,
    event: HANDLE,
    apcroutine: PIO_APC_ROUTINE,
    apccontext: *const c_void,
    iostatusblock: *mut IO_STATUS_BLOCK,
    segmentarray: *const FILE_SEGMENT_ELEMENT,
    length: u32,
    byteoffset: *const i64,
    key: *const u32,
) -> NTSTATUS;

// --- File Information & Attributes ---
type NTSETINFORMATIONFILE = extern "system" fn(
    filehandle: HANDLE,
    iostatusblock: *mut IO_STATUS_BLOCK,
    fileinformation: *const c_void,
    length: u32,
    fileinformationclass: u32,
) -> NTSTATUS;

type NTQUERYATTRIBUTESFILE = extern "system" fn(
    objectattributes: *mut OBJECT_ATTRIBUTES,
    fileattributes: *mut FILE_BASIC_INFORMATION,
) -> NTSTATUS;

type NTQUERYFULLATTRIBUTESFILE = extern "system" fn(
    objectattributes: *mut OBJECT_ATTRIBUTES,
    fileattributes: *mut FILE_NETWORK_OPEN_INFORMATION,
) -> NTSTATUS;

// --- Directory Operations ---
type NTQUERYDIRECTORYFILE = extern "system" fn(
    filehandle: HANDLE,
    event: HANDLE,
    apcroutine: PIO_APC_ROUTINE,
    apccontext: *const c_void,
    iostatusblock: *mut IO_STATUS_BLOCK,
    fileinformation: *mut c_void,
    length: u32,
    fileinformationclass: u32,
    returnsingleentry: BOOL,
    filename: *const UNICODE_STRING,
    restartscan: BOOL,
) -> NTSTATUS;

// --- File Cleanup & Closing ---
type NTDELETEFILE = extern "system" fn(objectattributes: *mut OBJECT_ATTRIBUTES) -> NTSTATUS;

// ============================================================================
// HOOK FUNCTION PROTOTYPES
// ============================================================================

static mut pOriginalNtCreateFile: NTCREATEFILE = NtCreateFile_tour;
static mut pOriginalNtOpenFile: NTOPENFILE = NtOpenFile_tour;
static mut pOriginalNtCreateSymbolicLinkObject: NTCREATESYMBOLICLINKOBJECT =
    NtCreateSymbolicLinkObject_tour;
static mut pOriginalNtOpenSymbolicLinkObject: NTOPENSYMBOLICLINKOBJECT =
    NtOpenSymbolicLinkObject_tour;
static mut pOriginalNtQuerySymbolicLinkObject: NTQUERYSYMBOLICLINKOBJECT =
    NtQuerySymbolicLinkObject_tour;
static mut pOriginalNtReadFile: NTREADFILE = NtReadFile_tour;
static mut pOriginalNtReadFileScatter: NTREADFILESCATTER = NtReadFileScatter_tour;
static mut pOriginalNtWriteFile: NTWRITEFILE = NtWriteFile_tour;
static mut pOriginalNtWriteFileGather: NTWRITEFILEGATHER = NtWriteFileGather_tour;
static mut pOriginalNtSetInformationFile: NTSETINFORMATIONFILE = NtSetInformationFile_tour;
static mut pOriginalNtQueryAttributesFile: NTQUERYATTRIBUTESFILE = NtQueryAttributesFile_tour;
static mut pOriginalNtQueryFullAttributesFile: NTQUERYFULLATTRIBUTESFILE =
    NtQueryFullAttributesFile_tour;
static mut pOriginalNtQueryDirectoryFile: NTQUERYDIRECTORYFILE = NtQueryDirectoryFile_tour;
static mut pOriginalNtDeleteFile: NTDELETEFILE = NtDeleteFile_tour;
static mut pOriginalCreateProcessInternalW: CREATEPROCESSINTERNALW = CreateProcessInternalW_tour;

// ============================================================================
// HOOK IMPLEMENTATIONS
// ============================================================================

// --- Process Creation ---

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

    if result.as_bool() && !processInformation.is_null() {
        let pi = unsafe { &*processInformation };
        let hprocess = pi.hProcess;
        let hthread = pi.hThread;

        // Propagate deny config to child process BEFORE injection
        let deny = shared::get_denied_paths();
        let deny = deny.iter().map(PathBuf::from).collect::<Vec<_>>();

        let child_id = unsafe { GetProcessId(hprocess) };
        if let Err(e) = shared::create_deny_config(child_id, &deny) {
            eprintln!(
                "[HOOK:CreateProcessInternalW] Failed to create deny config for child: {e:?}"
            );
            let _ = unsafe { TerminateProcess(hprocess, 1) };
            return BOOL(0);
        }

        if let Err(e) = shared::inject_dll(hprocess, unsafe { G_HINST_DLL }) {
            eprintln!("[HOOK:CreateProcessInternalW] Failed to inject into child process: {e:?}");
            eprintln!("[HOOK:CreateProcessInternalW] Terminating child process...");
            let _ = unsafe { TerminateProcess(hprocess, 1) };
            return BOOL(0);
        }

        if creationFlags & CREATE_SUSPENDED.0 == 0 {
            unsafe { ResumeThread(hthread) };
        }
    }

    result
}

// --- File Creation & Opening ---

extern "system" fn NtCreateFile_tour(
    filehandle: *mut HANDLE,
    desiredaccess: u32,
    objectattributes: *mut OBJECT_ATTRIBUTES,
    iostatusblock: *mut IO_STATUS_BLOCK,
    allocationsize: *const i64,
    fileattributes: u32,
    shareaccess: u32,
    createDisposition: u32,
    createoptions: u32,
    eabuffer: *const c_void,
    ealength: u32,
) -> NTSTATUS {
    let path = shared::get_path_from_object_attrs(objectattributes);
    if shared::is_path_denied(&path) {
        eprintln!("[HOOK:NtCreateFile] Denying access to {}", path);
        return STATUS_ACCESS_DENIED;
    }
    unsafe {
        pOriginalNtCreateFile(
            filehandle,
            desiredaccess,
            objectattributes,
            iostatusblock,
            allocationsize,
            fileattributes,
            shareaccess,
            createDisposition,
            createoptions,
            eabuffer,
            ealength,
        )
    }
}

extern "system" fn NtOpenFile_tour(
    filehandle: *mut HANDLE,
    desiredaccess: u32,
    objectattributes: *mut OBJECT_ATTRIBUTES,
    iostatusblock: *mut IO_STATUS_BLOCK,
    shareaccess: u32,
    openoptions: u32,
) -> NTSTATUS {
    let path = shared::get_path_from_object_attrs(objectattributes);
    if shared::is_path_denied(&path) {
        eprintln!("[HOOK:NtOpenFile] Denying access to {}", path);
        return STATUS_ACCESS_DENIED;
    }
    unsafe {
        pOriginalNtOpenFile(
            filehandle,
            desiredaccess,
            objectattributes,
            iostatusblock,
            shareaccess,
            openoptions,
        )
    }
}

// --- Symbolic Link Operations ---

extern "system" fn NtCreateSymbolicLinkObject_tour(
    linkhandle: *mut HANDLE,
    desiredaccess: u32,
    objectattributes: *mut OBJECT_ATTRIBUTES,
    linktarget: *const UNICODE_STRING,
) -> NTSTATUS {
    let path = shared::get_path_from_object_attrs(objectattributes);
    if shared::is_path_denied(&path) {
        eprintln!(
            "[HOOK:NtCreateSymbolicLinkObject] Denying access to {}",
            path
        );
        return STATUS_ACCESS_DENIED;
    }

    unsafe {
        pOriginalNtCreateSymbolicLinkObject(linkhandle, desiredaccess, objectattributes, linktarget)
    }
}

extern "system" fn NtOpenSymbolicLinkObject_tour(
    linkhandle: *mut HANDLE,
    desiredaccess: u32,
    objectattributes: *mut OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    let path = shared::get_path_from_object_attrs(objectattributes);
    if shared::is_path_denied(&path) {
        eprintln!("[HOOK:NtOpenSymbolicLinkObject] Denying access to {}", path);
        return STATUS_ACCESS_DENIED;
    }

    unsafe { pOriginalNtOpenSymbolicLinkObject(linkhandle, desiredaccess, objectattributes) }
}

extern "system" fn NtQuerySymbolicLinkObject_tour(
    linkhandle: HANDLE,
    linktarget: *mut UNICODE_STRING,
    returnedlength: *mut u32,
) -> NTSTATUS {
    let path = shared::get_path_from_handle(linkhandle);
    if shared::is_path_denied(&path) {
        eprintln!(
            "[HOOK:NtQuerySymbolicLinkObject] Denying access to {}",
            path
        );
        return STATUS_ACCESS_DENIED;
    }

    unsafe { pOriginalNtQuerySymbolicLinkObject(linkhandle, linktarget, returnedlength) }
}

// --- File Reading ---

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
    let path = shared::get_path_from_handle(filehandle);
    if shared::is_path_denied(&path) {
        eprintln!("[HOOK:NtReadFile] Denying access to {}", path);
        return STATUS_ACCESS_DENIED;
    }

    unsafe {
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
    }
}

extern "system" fn NtReadFileScatter_tour(
    filehandle: HANDLE,
    event: HANDLE,
    apcroutine: PIO_APC_ROUTINE,
    apccontext: *const c_void,
    iostatusblock: *mut IO_STATUS_BLOCK,
    segmentarray: *const FILE_SEGMENT_ELEMENT,
    length: u32,
    byteoffset: *const i64,
    key: *const u32,
) -> NTSTATUS {
    let path = shared::get_path_from_handle(filehandle);
    if shared::is_path_denied(&path) {
        eprintln!("[HOOK:NtReadFileScatter] Denying access to {}", path);
        return STATUS_ACCESS_DENIED;
    }

    unsafe {
        pOriginalNtReadFileScatter(
            filehandle,
            event,
            apcroutine,
            apccontext,
            iostatusblock,
            segmentarray,
            length,
            byteoffset,
            key,
        )
    }
}

// --- File Writing ---

extern "system" fn NtWriteFile_tour(
    filehandle: HANDLE,
    event: HANDLE,
    apcroutine: PIO_APC_ROUTINE,
    apccontext: *const c_void,
    iostatusblock: *mut IO_STATUS_BLOCK,
    buffer: *const c_void,
    length: u32,
    byteoffset: *const i64,
    key: *const u32,
) -> NTSTATUS {
    let path = shared::get_path_from_handle(filehandle);
    if shared::is_path_denied(&path) {
        eprintln!("[HOOK:NtWriteFile] Denying access to {}", path);
        return STATUS_ACCESS_DENIED;
    }

    unsafe {
        pOriginalNtWriteFile(
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
    }
}

extern "system" fn NtWriteFileGather_tour(
    filehandle: HANDLE,
    event: HANDLE,
    apcroutine: PIO_APC_ROUTINE,
    apccontext: *const c_void,
    iostatusblock: *mut IO_STATUS_BLOCK,
    segmentarray: *const FILE_SEGMENT_ELEMENT,
    length: u32,
    byteoffset: *const i64,
    key: *const u32,
) -> NTSTATUS {
    let path = shared::get_path_from_handle(filehandle);
    if shared::is_path_denied(&path) {
        eprintln!("[HOOK:NtWriteFileGather] Denying access to {}", path);
        return STATUS_ACCESS_DENIED;
    }

    unsafe {
        pOriginalNtWriteFileGather(
            filehandle,
            event,
            apcroutine,
            apccontext,
            iostatusblock,
            segmentarray,
            length,
            byteoffset,
            key,
        )
    }
}

// --- File Information & Attributes ---

extern "system" fn NtSetInformationFile_tour(
    filehandle: HANDLE,
    iostatusblock: *mut IO_STATUS_BLOCK,
    fileinformation: *const c_void,
    length: u32,
    fileinformationclass: u32,
) -> NTSTATUS {
    let path = shared::get_path_from_handle(filehandle);
    if shared::is_path_denied(&path) {
        eprintln!("[HOOK:NtSetInformationFile] Denying access to {}", path);
        return STATUS_ACCESS_DENIED;
    }

    unsafe {
        pOriginalNtSetInformationFile(
            filehandle,
            iostatusblock,
            fileinformation,
            length,
            fileinformationclass,
        )
    }
}

extern "system" fn NtQueryAttributesFile_tour(
    objectattributes: *mut OBJECT_ATTRIBUTES,
    fileattributes: *mut FILE_BASIC_INFORMATION,
) -> NTSTATUS {
    let path = shared::get_path_from_object_attrs(objectattributes);
    if shared::is_path_denied(&path) {
        eprintln!("[HOOK:NtQueryAttributesFile] Denying access to {}", path);
        return STATUS_ACCESS_DENIED;
    }

    unsafe { pOriginalNtQueryAttributesFile(objectattributes, fileattributes) }
}

extern "system" fn NtQueryFullAttributesFile_tour(
    objectattributes: *mut OBJECT_ATTRIBUTES,
    fileattributes: *mut FILE_NETWORK_OPEN_INFORMATION,
) -> NTSTATUS {
    let path = shared::get_path_from_object_attrs(objectattributes);
    if shared::is_path_denied(&path) {
        eprintln!(
            "[HOOK:NtQueryFullAttributesFile] Denying access to {}",
            path
        );
        return STATUS_ACCESS_DENIED;
    }

    unsafe { pOriginalNtQueryFullAttributesFile(objectattributes, fileattributes) }
}

// --- Directory Operations ---

extern "system" fn NtQueryDirectoryFile_tour(
    filehandle: HANDLE,
    event: HANDLE,
    apcroutine: PIO_APC_ROUTINE,
    apccontext: *const c_void,
    iostatusblock: *mut IO_STATUS_BLOCK,
    fileinformation: *mut c_void,
    length: u32,
    fileinformationclass: u32,
    returnsingleentry: BOOL,
    filename: *const UNICODE_STRING,
    restartscan: BOOL,
) -> NTSTATUS {
    let path = shared::get_path_from_handle(filehandle);
    if shared::is_path_denied(&path) {
        eprintln!("[HOOK:NtQueryDirectoryFile] Denying access to {}", path);
        return STATUS_ACCESS_DENIED;
    }

    unsafe {
        pOriginalNtQueryDirectoryFile(
            filehandle,
            event,
            apcroutine,
            apccontext,
            iostatusblock,
            fileinformation,
            length,
            fileinformationclass,
            returnsingleentry,
            filename,
            restartscan,
        )
    }
}

// --- File Cleanup & Closing ---

extern "system" fn NtDeleteFile_tour(objectattributes: *mut OBJECT_ATTRIBUTES) -> NTSTATUS {
    let path = shared::get_path_from_object_attrs(objectattributes);
    if shared::is_path_denied(&path) {
        eprintln!("[HOOK:NtDeleteFile] Denying access to {}", path);
        return STATUS_ACCESS_DENIED;
    }

    unsafe { pOriginalNtDeleteFile(objectattributes) }
}

// ============================================================================
// INITIALIZATION
// ============================================================================

macro_rules! install_hook {
    ($h_module:expr, $fn_name:literal, $original:ident, $hook:expr) => {
        if let Some(target) = GetProcAddress($h_module, s!($fn_name)) {
            let mut temp_orig: *mut c_void = std::ptr::null_mut();
            if MH_CreateHook(target as *mut c_void, $hook as *mut c_void, &mut temp_orig) != MH_OK {
                return Err(anyhow::anyhow!("Failed to create hook for {}", $fn_name));
            }

            if MH_EnableHook(target as *mut c_void) != MH_OK {
                return Err(anyhow::anyhow!("Failed to enable hook for {}", $fn_name));
            }

            $original = std::mem::transmute(temp_orig);
        }
    };
}

fn init_hooks() -> Result<()> {
    unsafe {
        if MH_Initialize() != MH_OK {
            anyhow::bail!("Failed to initialize MinHook");
        }

        let h_ntdll =
            GetModuleHandleW(w!("ntdll.dll")).context("Failed to get ntdll.dll handle")?;
        let h_kernelbase = GetModuleHandleW(w!("kernelbase.dll"))
            .context("Failed to get kernelbase.dll handle")?;

        // --- Process Creation ---
        install_hook!(
            h_kernelbase,
            "CreateProcessInternalW",
            pOriginalCreateProcessInternalW,
            CreateProcessInternalW_tour
        );

        // --- File Creation & Opening ---
        install_hook!(
            h_ntdll,
            "NtCreateFile",
            pOriginalNtCreateFile,
            NtCreateFile_tour
        );
        install_hook!(h_ntdll, "NtOpenFile", pOriginalNtOpenFile, NtOpenFile_tour);

        // --- Symbolic Link Operations ---
        install_hook!(
            h_ntdll,
            "NtCreateSymbolicLinkObject",
            pOriginalNtCreateSymbolicLinkObject,
            NtCreateSymbolicLinkObject_tour
        );
        install_hook!(
            h_ntdll,
            "NtOpenSymbolicLinkObject",
            pOriginalNtOpenSymbolicLinkObject,
            NtOpenSymbolicLinkObject_tour
        );
        install_hook!(
            h_ntdll,
            "NtQuerySymbolicLinkObject",
            pOriginalNtQuerySymbolicLinkObject,
            NtQuerySymbolicLinkObject_tour
        );

        // --- File Reading ---
        install_hook!(h_ntdll, "NtReadFile", pOriginalNtReadFile, NtReadFile_tour);
        install_hook!(
            h_ntdll,
            "NtReadFileScatter",
            pOriginalNtReadFileScatter,
            NtReadFileScatter_tour
        );

        // --- File Writing ---
        install_hook!(
            h_ntdll,
            "NtWriteFile",
            pOriginalNtWriteFile,
            NtWriteFile_tour
        );
        install_hook!(
            h_ntdll,
            "NtWriteFileGather",
            pOriginalNtWriteFileGather,
            NtWriteFileGather_tour
        );

        // --- File Information & Attributes ---
        install_hook!(
            h_ntdll,
            "NtSetInformationFile",
            pOriginalNtSetInformationFile,
            NtSetInformationFile_tour
        );
        install_hook!(
            h_ntdll,
            "NtQueryAttributesFile",
            pOriginalNtQueryAttributesFile,
            NtQueryAttributesFile_tour
        );
        install_hook!(
            h_ntdll,
            "NtQueryFullAttributesFile",
            pOriginalNtQueryFullAttributesFile,
            NtQueryFullAttributesFile_tour
        );

        // --- Directory Operations ---
        install_hook!(
            h_ntdll,
            "NtQueryDirectoryFile",
            pOriginalNtQueryDirectoryFile,
            NtQueryDirectoryFile_tour
        );

        // --- File Cleanup & Closing ---
        install_hook!(
            h_ntdll,
            "NtDeleteFile",
            pOriginalNtDeleteFile,
            NtDeleteFile_tour
        );
    }

    Ok(())
}

// ============================================================================
// DLL MAIN
// ============================================================================

static mut G_HINST_DLL: HINSTANCE = HINSTANCE(0 as _);

#[unsafe(no_mangle)]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(hinstDLL: HINSTANCE, fdw_reason: u32, _lpv_reserved: *mut ()) -> bool {
    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            unsafe { G_HINST_DLL = hinstDLL };
            shared::init_deny_config();
            if let Err(e) = init_hooks() {
                eprintln!("[HOOK] Failed to initialize hooks: {e}");
            }
        }
        DLL_PROCESS_DETACH => {
            let _ = unsafe { MH_Uninitialize() };
        }
        _ => (),
    }

    true
}
