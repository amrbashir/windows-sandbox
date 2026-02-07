#![feature(windows_process_extensions_main_thread_handle)]

use std::os::windows::io::AsRawHandle;
use std::os::windows::process::{ChildExt, CommandExt};
use std::process::Command;

use windows::Win32::Foundation::*;
use windows::Win32::System::JobObjects::*;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::*;

fn main() -> windows::core::Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() < 1 {
        eprintln!("[SANDBOX] Please provide a command to run in the sandbox.");
        return Ok(());
    }

    eprintln!("[SANDBOX] Starting...");

    eprintln!("[SANDBOX] Creating job object...");
    let h_job = unsafe { CreateJobObjectW(None, None)? };

    // Configure job limits
    let mut info: JOBOBJECT_BASIC_LIMIT_INFORMATION = Default::default();
    info.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

    let mut extended: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = Default::default();
    extended.BasicLimitInformation = info;

    unsafe {
        SetInformationJobObject(
            h_job,
            JobObjectExtendedLimitInformation,
            &extended as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )?;
    }

    eprintln!("[SANDBOX] Creating process...");
    let mut child = Command::new(&args[0])
        .args(&args[1..])
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .creation_flags(CREATE_SUSPENDED.0)
        .spawn()?;

    let h_process = HANDLE(child.as_raw_handle() as _);
    let h_thread = HANDLE(child.main_thread_handle().as_raw_handle() as _);

    eprintln!("[SANDBOX] Assigning to job object...");
    unsafe { AssignProcessToJobObject(h_job, h_process)? };

    eprintln!("[SANDBOX] Injecting DLL...");
    let process = shared::Process::from_raw_handle(h_process);
    let hinstance = unsafe { GetModuleHandleW(None)? };
    shared::inject_dll(process, HINSTANCE(hinstance.0))?;

    eprintln!("[SANDBOX] Resuming process thread...");
    eprintln!(); // Blank line for readability
    unsafe { ResumeThread(h_thread) };

    // Wait for process to exit
    child.wait()?;

    // Clean up job object
    unsafe { CloseHandle(h_job)? };

    Ok(())
}
