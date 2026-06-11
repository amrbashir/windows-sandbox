use anyhow::Result;
use clap::Parser;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::LazyLock;
use windows::Win32::Foundation::*;
use windows::Win32::System::JobObjects::*;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Threading::*;
use windows::core::{s, w};

#[allow(non_snake_case)]
type NtGetNextThreadFn = unsafe extern "system" fn(
	ProcessHandle: HANDLE,
	ThreadHandle: HANDLE,
	DesiredAccess: u32,
	HandleAttributes: u32,
	Flags: u32,
	NewThreadHandle: *mut HANDLE,
) -> NTSTATUS;

#[allow(non_upper_case_globals)]
static NtGetNextThread: LazyLock<Option<NtGetNextThreadFn>> = LazyLock::new(|| {
	let ntdll = unsafe { GetModuleHandleW(w!("ntdll.dll")) }.ok()?;
	let address = unsafe { GetProcAddress(ntdll, s!("NtGetNextThread")) }?;
	unsafe { std::mem::transmute(address) }
});

/// Get's the handle of the main thread of a process in stable rust.
pub unsafe fn get_main_thread_handle(
	hprocess: HANDLE,
	desired_access: u32,
) -> windows::core::Result<HANDLE> {
	if let Some(nt_get_next_thread) = *NtGetNextThread {
		let mut hthread = HANDLE::default();
		let status =
			unsafe { nt_get_next_thread(hprocess, hthread, desired_access, 0, 0, &mut hthread) };

		if status == STATUS_SUCCESS {
			return Ok(hthread);
		}
	}

	return Err(windows::core::Error::from_thread());
}

#[derive(Parser, Debug)]
#[command(name = "sandbox")]
#[command(about = "Run commands in a sandboxed environment with file access restrictions")]
#[command(trailing_var_arg = true)]
struct Args {
	/// Paths to deny access to (can be specified multiple times)
	#[arg(long, value_name = "PATH")]
	deny: Vec<PathBuf>,

	/// The command to run in the sandbox (including all arguments)
	#[arg(trailing_var_arg = true, required = true)]
	command: Vec<String>,
}

fn main() -> Result<()> {
	let args = Args::parse();

	if args.command.is_empty() {
		eprintln!("[SANDBOX] Please provide a command to run in the sandbox.");
		std::process::exit(1);
	}

	eprintln!("[SANDBOX] Starting...");

	eprintln!("[SANDBOX] Creating job object...");
	let hjob = unsafe { CreateJobObjectW(None, None)? };

	// Configure job limits
	let mut info: JOBOBJECT_BASIC_LIMIT_INFORMATION = Default::default();
	info.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

	let mut extended: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = Default::default();
	extended.BasicLimitInformation = info;

	unsafe {
		SetInformationJobObject(
			hjob,
			JobObjectExtendedLimitInformation,
			&extended as *const _ as *const _,
			std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
		)?;
	}

	eprintln!("[SANDBOX] Creating process...");
	let mut child = Command::new(&args.command[0])
		.args(&args.command[1..])
		.stdout(std::process::Stdio::inherit())
		.stderr(std::process::Stdio::inherit())
		.creation_flags(CREATE_SUSPENDED.0)
		.spawn()?;

	let hprocess = HANDLE(child.as_raw_handle() as _);
	let hthread = unsafe { get_main_thread_handle(hprocess, THREAD_SUSPEND_RESUME.0)? };

	// Create shared memory with deny list before assigning to job
	if !args.deny.is_empty() {
		eprintln!("[SANDBOX] Creating deny list configuration...");
		let deny = args.deny.iter().filter_map(|p| p.canonicalize().ok());
		let deny = deny.collect::<Vec<_>>();
		if !deny.is_empty() {
			let _ = shared::create_deny_config(child.id(), &deny)?;
		}
	}

	eprintln!("[SANDBOX] Assigning to job object...");
	unsafe { AssignProcessToJobObject(hjob, hprocess)? };

	eprintln!("[SANDBOX] Injecting DLL...");
	let hinstance = unsafe { GetModuleHandleW(None)? };
	shared::inject_dll(hprocess, HINSTANCE(hinstance.0))?;

	eprintln!("[SANDBOX] Resuming process thread...");
	unsafe { ResumeThread(hthread) };

	// Wait for process to exit
	child.wait()?;

	// Clean up job object
	unsafe { CloseHandle(hjob)? };

	Ok(())
}
