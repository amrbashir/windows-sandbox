use anyhow::Result;
use clap::Parser;
use std::io::{Read, Write};
use std::path::PathBuf;
use windows::Win32::Foundation::*;
use windows::Win32::System::Console::*;
use windows::Win32::System::JobObjects::*;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::Threading::*;
use windows::core::{PCWSTR, PWSTR};

/// Allocates and initialises a `PROC_THREAD_ATTRIBUTE_LIST` large enough to
/// hold `count` attributes.  Returns the opaque byte buffer that backs it.
fn alloc_proc_thread_attr_list(count: u32) -> Result<Vec<u8>> {
	let mut size: usize = 0;
	// First call with null pointer – always "fails" with ERROR_INSUFFICIENT_BUFFER
	// but fills in the required size.
	unsafe {
		let _ = InitializeProcThreadAttributeList(None, count, Some(0), &mut size);
	}
	let mut buf = vec![0u8; size];
	unsafe {
		InitializeProcThreadAttributeList(
			Some(LPPROC_THREAD_ATTRIBUTE_LIST(buf.as_mut_ptr() as _)),
			count,
			Some(0),
			&mut size,
		)?;
	}
	Ok(buf)
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

	// ── ConPTY setup ─────────────────────────────────────────────────────────

	eprintln!("[SANDBOX] Creating ConPTY pipes...");
	let (pty_in_read, pty_in_write) = unsafe {
		let (mut r, mut w) = (HANDLE::default(), HANDLE::default());
		CreatePipe(&mut r, &mut w, None, 0)?;
		(r, w)
	};
	let (pty_out_read, pty_out_write) = unsafe {
		let (mut r, mut w) = (HANDLE::default(), HANDLE::default());
		CreatePipe(&mut r, &mut w, None, 0)?;
		(r, w)
	};

	eprintln!("[SANDBOX] Creating PseudoConsole...");
	// Query the real console size so the PTY matches the visible terminal.
	let console_size = unsafe {
		let mut csbi: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
		if GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE)?, &mut csbi).is_ok() {
			COORD {
				X: csbi.srWindow.Right - csbi.srWindow.Left + 1,
				Y: csbi.srWindow.Bottom - csbi.srWindow.Top + 1,
			}
		} else {
			COORD { X: 120, Y: 30 }
		}
	};
	let hpcon = unsafe { CreatePseudoConsole(console_size, pty_in_read, pty_out_write, 0)? };

	// The PTY owns these ends now – close our copies so the pipes drain properly.
	unsafe {
		CloseHandle(pty_in_read)?;
		CloseHandle(pty_out_write)?;
	}

	// ── Job object ───────────────────────────────────────────────────────────

	eprintln!("[SANDBOX] Creating job object...");
	let hjob = unsafe { CreateJobObjectW(None, None)? };

	let mut extended: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = Default::default();
	extended.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
	unsafe {
		SetInformationJobObject(
			hjob,
			JobObjectExtendedLimitInformation,
			&extended as *const _ as *const _,
			std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
		)?;
	}

	// ── Spawn process via CreateProcessW with STARTUPINFOEXW ─────────────────

	eprintln!("[SANDBOX] Creating process in ConPTY...");

	// Build writable UTF-16 command-line buffer.
	let cmdline_str = args.command.join(" ");
	let mut cmdline_wide: Vec<u16> = cmdline_str
		.encode_utf16()
		.chain(std::iter::once(0))
		.collect();

	// Set up the extended startup info with the PTY attribute.
	let mut attr_buf = alloc_proc_thread_attr_list(1)?;
	let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as _);

	// PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016
	const PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE: usize = 0x00020016;
	unsafe {
		UpdateProcThreadAttribute(
			attr_list,
			0,
			PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
			Some(hpcon.0 as *const _),
			std::mem::size_of::<HPCON>(),
			None,
			None,
		)?;
	}

	let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
	si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
	si.lpAttributeList = attr_list;

	let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

	unsafe {
		CreateProcessW(
			PCWSTR::null(),
			Some(PWSTR(cmdline_wide.as_mut_ptr())),
			None,
			None,
			false,
			EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
			None,
			PCWSTR::null(),
			&si.StartupInfo,
			&mut pi,
		)?;
	}

	let hprocess = pi.hProcess;
	let hthread = pi.hThread;
	let pid = pi.dwProcessId;

	// Clean up the attribute list (process is already created).
	unsafe { DeleteProcThreadAttributeList(attr_list) };

	// ── Deny-list shared memory ───────────────────────────────────────────────

	if !args.deny.is_empty() {
		eprintln!("[SANDBOX] Creating deny list configuration...");
		let deny: Vec<_> = args
			.deny
			.iter()
			.filter_map(|p| p.canonicalize().ok())
			.collect();
		if !deny.is_empty() {
			shared::create_deny_config(pid, &deny)?;
		}
	}

	// ── Assign to job, inject DLL, resume ────────────────────────────────────

	eprintln!("[SANDBOX] Assigning to job object...");
	unsafe { AssignProcessToJobObject(hjob, hprocess)? };

	eprintln!("[SANDBOX] Injecting DLL...");
	let hinstance = unsafe { GetModuleHandleW(None)? };
	shared::inject_dll(hprocess, HINSTANCE(hinstance.0))?;

	eprintln!("[SANDBOX] Resuming process thread...");
	unsafe { ResumeThread(hthread) };

	// ── I/O forwarding ───────────────────────────────────────────────────────

	// stdin  → PTY input
	let pty_in_write_raw = pty_in_write.0 as isize;
	let stdin_to_pty = std::thread::spawn(move || {
		let mut stdin = std::io::stdin().lock();
		let mut buf = [0u8; 1024];
		// SAFETY: handle is valid for the life of this thread.
		let write_handle = HANDLE(pty_in_write_raw as _);
		loop {
			let n = match stdin.read(&mut buf) {
				Ok(0) | Err(_) => break,
				Ok(n) => n,
			};
			let mut written = 0u32;
			if unsafe {
				windows::Win32::Storage::FileSystem::WriteFile(
					write_handle,
					Some(&buf[..n]),
					Some(&mut written),
					None,
				)
			}
			.is_err()
			{
				break;
			}
		}
	});

	// PTY output → stdout
	let pty_out_read_raw = pty_out_read.0 as isize;
	let pty_to_stdout = std::thread::spawn(move || {
		let mut stdout = std::io::stdout().lock();
		let mut buf = [0u8; 4096];
		let read_handle = HANDLE(pty_out_read_raw as _);
		loop {
			let mut read = 0u32;
			let ok = unsafe {
				windows::Win32::Storage::FileSystem::ReadFile(
					read_handle,
					Some(&mut buf),
					Some(&mut read),
					None,
				)
			};
			if ok.is_err() || read == 0 {
				break;
			}
			if stdout.write_all(&buf[..read as usize]).is_err() {
				break;
			}
			let _ = stdout.flush();
		}
	});

	// ── Wait for process ─────────────────────────────────────────────────────

	unsafe { WaitForSingleObject(hprocess, INFINITE) };

	// Close PTY – this signals EOF to the output pipe so the reader thread exits.
	unsafe { ClosePseudoConsole(hpcon) };
	unsafe {
		CloseHandle(pty_in_write)?;
	}
	unsafe {
		CloseHandle(pty_out_read)?;
	}

	let _ = pty_to_stdout.join();
	let _ = stdin_to_pty.join();

	unsafe {
		CloseHandle(hthread)?;
		CloseHandle(hprocess)?;
		CloseHandle(hjob)?;
	}

	Ok(())
}
