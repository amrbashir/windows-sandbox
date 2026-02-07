#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

use minhook_detours::*;
use std::ffi::c_void;
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

type NTCREATENAMEDPIPEFILE = extern "system" fn(
    filehandle: *mut HANDLE,
    desiredaccess: u32,
    objectattributes: *mut OBJECT_ATTRIBUTES,
    iostatusblock: *mut IO_STATUS_BLOCK,
    shareaccess: u32,
    createdisposition: u32,
    createoptions: u32,
    namedpipetype: u32,
    readmodemode: u32,
    completionmode: u32,
    maximuminstances: u32,
    inboundquota: u32,
    outboundquota: u32,
    defaulttimeout: *const i64,
) -> NTSTATUS;

type NTCREATEMAILSLOTFILE = extern "system" fn(
    filehandle: *mut HANDLE,
    desiredaccess: u32,
    objectattributes: *mut OBJECT_ATTRIBUTES,
    iostatusblock: *mut IO_STATUS_BLOCK,
    createoptions: u32,
    mailslotquota: u32,
    maxmessagesize: u32,
    readtimeout: *const i64,
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
static mut pOriginalNtCreateNamedPipeFile: NTCREATENAMEDPIPEFILE = NtCreateNamedPipeFile_tour;
static mut pOriginalNtCreateMailslotFile: NTCREATEMAILSLOTFILE = NtCreateMailslotFile_tour;
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
        let thread = pi.hThread;

        let process = shared::Process::from_raw_handle(hprocess);
        if let Err(e) = shared::inject_dll(process, unsafe { G_HINST_DLL }) {
            eprintln!("[HOOK:CreateProcessInternalW] Failed to inject into child process: {e:?}");
            eprintln!("[HOOK:CreateProcessInternalW] Terminating child process...");
            let _ = unsafe { TerminateProcess(hprocess, 1) };
            return BOOL(0);
        }

        if creationFlags & CREATE_SUSPENDED.0 == 0 {
            unsafe { ResumeThread(thread) };
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
    if shared::check_and_deny(&path, "NtCreateFile") {
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
    if shared::check_and_deny(&path, "NtOpenFile") {
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

extern "system" fn NtCreateNamedPipeFile_tour(
    filehandle: *mut HANDLE,
    desiredaccess: u32,
    objectattributes: *mut OBJECT_ATTRIBUTES,
    iostatusblock: *mut IO_STATUS_BLOCK,
    shareaccess: u32,
    createdisposition: u32,
    createoptions: u32,
    namedpipetype: u32,
    readmodemode: u32,
    completionmode: u32,
    maximuminstances: u32,
    inboundquota: u32,
    outboundquota: u32,
    defaulttimeout: *const i64,
) -> NTSTATUS {
    let path = shared::get_path_from_object_attrs(objectattributes);
    if shared::check_and_deny(&path, "NtCreateNamedPipeFile") {
        return STATUS_ACCESS_DENIED;
    }
    unsafe {
        pOriginalNtCreateNamedPipeFile(
            filehandle,
            desiredaccess,
            objectattributes,
            iostatusblock,
            shareaccess,
            createdisposition,
            createoptions,
            namedpipetype,
            readmodemode,
            completionmode,
            maximuminstances,
            inboundquota,
            outboundquota,
            defaulttimeout,
        )
    }
}

extern "system" fn NtCreateMailslotFile_tour(
    filehandle: *mut HANDLE,
    desiredaccess: u32,
    objectattributes: *mut OBJECT_ATTRIBUTES,
    iostatusblock: *mut IO_STATUS_BLOCK,
    createoptions: u32,
    mailslotquota: u32,
    maxmessagesize: u32,
    readtimeout: *const i64,
) -> NTSTATUS {
    let path = shared::get_path_from_object_attrs(objectattributes);
    if shared::check_and_deny(&path, "NtCreateMailslotFile") {
        return STATUS_ACCESS_DENIED;
    }
    unsafe {
        pOriginalNtCreateMailslotFile(
            filehandle,
            desiredaccess,
            objectattributes,
            iostatusblock,
            createoptions,
            mailslotquota,
            maxmessagesize,
            readtimeout,
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
    if shared::check_and_deny(&path, "NtCreateSymbolicLinkObject") {
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
    if shared::check_and_deny(&path, "NtOpenSymbolicLinkObject") {
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
    if shared::check_and_deny(&path, "NtQuerySymbolicLinkObject") {
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
    if shared::check_and_deny(&path, "NtReadFile") {
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
    if shared::check_and_deny(&path, "NtReadFileScatter") {
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
    if shared::check_and_deny(&path, "NtWriteFile") {
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
    if shared::check_and_deny(&path, "NtWriteFileGather") {
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
    if shared::check_and_deny(&path, "NtSetInformationFile") {
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
    if shared::check_and_deny(&path, "NtQueryAttributesFile") {
        return STATUS_ACCESS_DENIED;
    }
    unsafe { pOriginalNtQueryAttributesFile(objectattributes, fileattributes) }
}

extern "system" fn NtQueryFullAttributesFile_tour(
    objectattributes: *mut OBJECT_ATTRIBUTES,
    fileattributes: *mut FILE_NETWORK_OPEN_INFORMATION,
) -> NTSTATUS {
    let path = shared::get_path_from_object_attrs(objectattributes);
    if shared::check_and_deny(&path, "NtQueryFullAttributesFile") {
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
    if shared::check_and_deny(&path, "NtQueryDirectoryFile") {
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
    if shared::check_and_deny(&path, "NtDeleteFile") {
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
                return;
            }

            if MH_EnableHook(target as *mut c_void) != MH_OK {
                return;
            }

            $original = std::mem::transmute(temp_orig);
        }
    };
}

fn init_hooks() {
    unsafe {
        if MH_Initialize() != MH_OK {
            eprintln!("[INIT] Failed to initialize MinHook");
            return;
        }

        let h_ntdll = GetModuleHandleW(w!("ntdll.dll")).unwrap();
        let h_kernelbase = GetModuleHandleW(w!("kernelbase.dll")).unwrap();

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
        install_hook!(
            h_ntdll,
            "NtCreateNamedPipeFile",
            pOriginalNtCreateNamedPipeFile,
            NtCreateNamedPipeFile_tour
        );
        install_hook!(
            h_ntdll,
            "NtCreateMailslotFile",
            pOriginalNtCreateMailslotFile,
            NtCreateMailslotFile_tour
        );

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
            init_hooks();
        }
        DLL_PROCESS_DETACH => {
            let _ = unsafe { MH_Uninitialize() };
        }
        _ => (),
    }

    true
}
