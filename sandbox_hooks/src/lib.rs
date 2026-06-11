#![allow(unsafe_op_in_unsafe_fn)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use anyhow::{Context, Result};
use minhook_detours::*;
use std::ffi::c_void;
use std::path::PathBuf;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::Foundation::NTSTATUS;
use windows::Win32::Foundation::STATUS_ACCESS_DENIED;
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::Win32::System::IO::PIO_APC_ROUTINE;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::System::Threading::CREATE_SUSPENDED;
use windows::Win32::System::Threading::GetProcessId;
use windows::Win32::System::Threading::TerminateProcess;
use windows::Win32::System::Threading::{PROCESS_INFORMATION, ResumeThread, STARTUPINFOW};
use windows::core::BOOL;
use windows::core::w;

/// Global variable to store the DLL instance handle.
static mut G_HINST_DLL: HINSTANCE = HINSTANCE(0 as _);

/// DllMain is the entry point for the DLL.
#[unsafe(no_mangle)]
extern "system" fn DllMain(hinst_dll: HINSTANCE, fdw_reason: u32, _lpv_reserved: *mut ()) -> bool {
	if fdw_reason == DLL_PROCESS_ATTACH {
		// Store the DLL instance handle
		unsafe { G_HINST_DLL = hinst_dll };

		shared::init_deny_config();

		if let Err(e) = unsafe { init_hooks() } {
			eprintln!("[HOOK] Failed to initialize hooks: {e}");
		}
	};

	true
}

unsafe fn init_hooks() -> Result<()> {
	// Get modules needed for hooking
	let hntdll = GetModuleHandleW(w!("ntdll.dll")).context("ntdll.dll not found")?;
	let hkernelbase = GetModuleHandleW(w!("kernelbase.dll")).context("kernelbase.dll not found")?;

	// Initialize MinHook
	if MH_Initialize() != MH_OK {
		anyhow::bail!("Failed to initialize MinHook");
	}

	register_createprocessinternalw(hkernelbase)?;
	register_ntreadfile(hntdll)?;

	Ok(())
}

/// Define a hook with the given signature and body, and automatically call the original function at
/// the end of the hook.
///
/// Must be called inside a function so the hook can be registered at runtime.
#[macro_export]
macro_rules! define_auto_hook {
    (
        unsafe extern "system" fn
        $fn_name:ident($($param_name:ident : $param_type:ty),* $(,)?) ->
        $return_type:ty { $($body:tt)* }
    ) => {
        pastey::paste! {
            $crate::define_hook!(
                unsafe extern "system" fn
                $fn_name($($param_name : $param_type),*) ->
                $return_type {
                    $($body)*

                    // Call the original function
                    unsafe { [< pOriginal $fn_name >]($($param_name),*) }
                }
            );
        }
    };
}

/// Define a hook with the given signature and body.
///
/// Must be called inside a function so the hook can be registered at runtime.
///
/// Does NOT call the original function, the hook body can call it manually if needed using the
/// generated `pOriginal{FnName}` function pointer.
#[macro_export]
macro_rules! define_hook {
    (
        unsafe extern "system" fn
        $fn_name:ident($($param_name:ident : $param_type:ty),* $(,)?) ->
        $return_type:ty { $($body:tt)* }
    ) => {
        pastey::paste! {
            // Define a type for the original function pointer
            type [< $fn_name:upper >] = unsafe extern "system" fn($($param_name : $param_type),*) -> $return_type;

            // Define a static mutable variable to hold the original function pointer
            pub static mut [< pOriginal $fn_name >]: [< $fn_name:upper >] = $fn_name;

            // Define the hook function
            unsafe extern "system" fn $fn_name($($param_name : $param_type),*) -> $return_type {
                $($body)*
            }

            // Define a function to register the hook at runtime
            pub unsafe fn [< register_ $fn_name:lower >](hmodule: ::windows::Win32::Foundation::HMODULE) -> ::anyhow::Result<()> {
                use ::std::ffi::c_void;

                // Get the address of the target function
                let name = ::std::stringify!($fn_name);
                let cname = ::std::format!("{name}\0");
                let pcname = ::windows::core::PCSTR::from_raw(cname.as_ptr());
                let Some(address) = ::windows::Win32::System::LibraryLoader::GetProcAddress(hmodule, pcname) else {
                    ::anyhow::bail!("Failed to get address of function {name} from module {hmodule:?}");
                };

                // Create the hook
                let mut original: *mut c_void = ::std::ptr::null_mut();
                if ::minhook_detours::MH_CreateHook(address as *mut c_void, $fn_name as *mut c_void, &mut original) != ::minhook_detours::MH_OK {
                    ::anyhow::bail!("Failed to create hook for function {name}");
                }

                // Enable the hook
                if ::minhook_detours::MH_EnableHook(address as *mut c_void) != ::minhook_detours::MH_OK {
                    ::anyhow::bail!("Failed to enable hook for function {name}");
                }

                // Store the original function pointer in the static variable
                [< pOriginal $fn_name >] = ::std::mem::transmute(original);

                ::anyhow::Ok(())
            }
        }
    };
}

crate::define_hook! {
	unsafe extern "system" fn CreateProcessInternalW(
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
}

crate::define_auto_hook! {
	unsafe extern "system" fn NtReadFile(
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
	}
}
