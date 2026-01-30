use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::ServerOptions;

struct DaemonChild {
    child: Child,
    stdin: std::process::ChildStdin,
    stdout: std::process::ChildStdout,
}

#[derive(Default)]
struct State {
    daemon_32: Option<DaemonChild>,
}

fn ensure_32_bit_daemon(state: &mut State, injector_path: &Path) -> std::io::Result<()> {
    if let Some(ref mut d) = state.daemon_32 {
        match d.child.try_wait() {
            Ok(Some(_)) => state.daemon_32 = None,
            Ok(None) => return Ok(()),
            Err(_) => state.daemon_32 = None,
        }
    }

    let mut child = Command::new(injector_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("Failed to take stdin"))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("Failed to take stdout"))?;

    state.daemon_32 = Some(DaemonChild {
        child,
        stdin,
        stdout,
    });

    Ok(())
}

async fn inject_via_32_daemon(
    pid: u32,
    state: &mut State,
    daemon_32_path: &Path,
) -> std::io::Result<u8> {
    if let Err(_) = ensure_32_bit_daemon(state, daemon_32_path) {
        return Ok(1);
    }

    let daemon = state.daemon_32.as_mut().unwrap();
    let pid_bytes = pid.to_le_bytes();

    if let Err(_) = daemon.stdin.write_all(&pid_bytes) {
        state.daemon_32 = None;
        return Ok(1);
    }
    if let Err(_) = daemon.stdin.flush() {
        state.daemon_32 = None;
        return Ok(1);
    }

    let mut resp = [0; 1];
    if let Err(_) = daemon.stdout.read_exact(&mut resp) {
        state.daemon_32 = None;
        return Ok(1);
    }

    Ok(resp[0])
}

const MAX_INSTANCES: u32 = 1;
const MAX_BUFFER_SIZE: u32 = 4 * 1024;

pub fn start() -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut state = State::default();

        let current_exe = std::env::current_exe().unwrap();
        let current_exe_dir = current_exe.parent().unwrap();
        let daemon_32_path = current_exe_dir.join("sandbox_daemon32.exe");

        let pipe_name = shared::PIPE_NAME;

        loop {
            let server = match ServerOptions::new()
                .max_instances(MAX_INSTANCES as usize)
                .in_buffer_size(MAX_BUFFER_SIZE)
                .out_buffer_size(MAX_BUFFER_SIZE)
                .create(pipe_name)
            {
                Ok(s) => s,
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };

            if let Err(_) = server.connect().await {
                continue;
            }

            let mut server = server;
            let mut buf = [0u8; 4];

            match server.read_exact(&mut buf).await {
                Ok(_) => {
                    let pid = u32::from_le_bytes(buf);
                    println!("[DAEMON] Received inject request for PID {pid}");

                    let process = shared::Process::open(pid).unwrap();
                    let is_target_64 = process.is_64_bit().unwrap_or_default();

                    let status = if is_target_64 {
                        println!("[DAEMON] Injecting directly (64-bit target)");
                        match shared::inject_dll(*process, is_target_64) {
                            Ok(_) => {
                                println!("[DAEMON] Direct injection succeeded");
                                0u8
                            }
                            Err(e) => {
                                println!("[DAEMON] Direct injection failed: {:?}", e);
                                1u8
                            }
                        }
                    } else {
                        println!("[DAEMON] Spawning 32-bit injector");
                        inject_via_32_daemon(pid, &mut state, &daemon_32_path)
                            .await
                            .unwrap_or(1)
                    };

                    if let Err(e) = server.write_all(&[status]).await {
                        println!("[DAEMON] Failed to write status to pipe: {:?}", e);
                    }
                }
                Err(e) => {
                    println!("[DAEMON] Failed to read from pipe: {:?}", e);
                }
            }

            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
}
