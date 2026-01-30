use windows::Win32::Foundation::*;
use windows::Win32::System::JobObjects::*;
use windows::Win32::System::Threading::*;
use windows::core::PWSTR;

mod daemon;

#[tokio::main]
pub async fn main() -> windows::core::Result<()> {
    // Start injector pipe server thread
    let _daemon = daemon::start();

    println!("[HOST] Starting sandbox...");

    println!("[HOST] Creating job object...");
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

    // Spawn a process
    let mut si: STARTUPINFOW = Default::default();
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

    let mut pi: PROCESS_INFORMATION = Default::default();

    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() < 1 {
        println!("[HOST] Please provide a command to run in the sandbox.");
        return Ok(());
    }

    let mut cmd = shared::encode_wide(&args.join(" "));

    println!("[HOST] Creating process...");
    unsafe {
        CreateProcessW(
            None,
            Some(PWSTR(cmd.as_mut_ptr() as _)),
            None,
            None,
            false,
            CREATE_SUSPENDED,
            None,
            None,
            &si,
            &mut pi,
        )?;
    }
    println!("[HOST] Process created with PID: {:?}", pi.dwProcessId);

    println!("[HOST] Assigning to job object...");
    unsafe { AssignProcessToJobObject(h_job, pi.hProcess)? };

    let process = shared::Process::from_raw_handle(pi.hProcess);
    shared::inject_dll_into_process_async(process).await?;

    println!("[HOST] Resuming process thread...");
    unsafe { ResumeThread(pi.hThread) };

    // Wait for process to exit
    unsafe { WaitForSingleObject(pi.hProcess, INFINITE) };

    // Clean up
    unsafe {
        CloseHandle(pi.hProcess)?;
        CloseHandle(pi.hThread)?;
        CloseHandle(h_job)?;
    }

    Ok(())
}
