use std::io::{Read, Write};

#[tokio::main]
async fn main() -> windows::core::Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut in_lock = stdin.lock();
    let mut out_lock = stdout.lock();

    println!("[DAEMON32] Started");

    loop {
        let mut pid_bytes = [0u8; 4];
        match in_lock.read_exact(&mut pid_bytes) {
            Ok(_) => {
                let pid = u32::from_le_bytes(pid_bytes);
                println!("[DAEMON32] Received PID: {}", pid);

                let process = shared::Process::open(pid)?;

                let status = match shared::inject_dll(*process, process.is_64_bit()?) {
                    Ok(_) => {
                        println!("[DAEMON32] Injection succeeded");
                        0u8
                    }
                    Err(e) => {
                        println!("[DAEMON32] Injection failed: {:?}", e);
                        1u8
                    }
                };
                if let Err(e) = out_lock.write_all(&[status]) {
                    println!("[DAEMON32] Failed to write status: {:?}", e);
                    break;
                }
                if let Err(e) = out_lock.flush() {
                    println!("[DAEMON32] Failed to flush: {:?}", e);
                    break;
                }
            }
            Err(e) => {
                println!("[DAEMON32] Failed to read: {:?}", e);
                break;
            }
        }
    }

    println!("[DAEMON32] Exiting");

    Ok(())
}
