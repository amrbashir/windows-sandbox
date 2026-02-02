$SANDBOX_DIR = "$env:CARGO_TARGET_DIR/debug"
$X64_DIR = "$env:CARGO_TARGET_DIR/x86_64-pc-windows-msvc/debug"
$X32_DIR = "$env:CARGO_TARGET_DIR/i686-pc-windows-msvc/debug"

# Build the sandbox hooks DLLs
cargo build -p sandbox_hooks --target x86_64-pc-windows-msvc
cargo build -p sandbox_hooks --target i686-pc-windows-msvc

# Move the built DLLs to the sandbox directory
Move-Item "$X64_DIR/sandbox_hooks.dll" "$SANDBOX_DIR/sandbox_hooks_64.dll" -Force
Move-Item "$X32_DIR/sandbox_hooks.dll" "$SANDBOX_DIR/sandbox_hooks_32.dll" -Force

# for UWP apps to be able to load the DLL, we need to give them read & execute permissions
icacls "$SANDBOX_DIR/sandbox_hooks_64.dll" /grant everyone:RX
icacls "$SANDBOX_DIR/sandbox_hooks_64.dll" /grant *S-1-15-2-1:RX
icacls "$SANDBOX_DIR/sandbox_hooks_64.dll" /grant *S-1-15-2-2:RX
icacls "$SANDBOX_DIR/sandbox_hooks_32.dll" /grant everyone:RX
icacls "$SANDBOX_DIR/sandbox_hooks_32.dll" /grant *S-1-15-2-1:RX
icacls "$SANDBOX_DIR/sandbox_hooks_32.dll" /grant *S-1-15-2-2:RX

# Build the 32-bit sandbox daemon binaries and move them to the sandbox directory
cargo build --bin sandbox_daemon32 --target i686-pc-windows-msvc
Move-Item "$X32_DIR/sandbox_daemon32.exe" "$SANDBOX_DIR/sandbox_daemon32.exe" -Force

# Run the sandbox
cargo run --bin sandbox -- "C:\Users\amr\scoop\apps\uutils-coreutils\current\coreutils.exe cat ./test/secret.txt"
cargo run --bin sandbox -- "powershell.exe -Command  C:\Users\amr\scoop\apps\uutils-coreutils\current\coreutils.exe cat ./test/secret.txt"
cargo run --bin sandbox -- "C:\Users\amr\scoop\shims\cat.exe ./test/secret.txt"
cargo run --bin sandbox -- "powershell.exe -Command  C:\Users\amr\scoop\shims\cat.exe ./test/secret.txt"
# cargo run --bin sandbox -- "notepad.exe ./test/secret.txt"
# cargo run --bin sandbox -- "pwsh.exe"