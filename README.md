# lattica-tools
Tools for building Lattica applications

## Run Guide

### Option A: Prebuilt binaries (recommended)
- Required: `--port <u16>`  
- Optional: `--key-path <FILE>` (defaults to `./secret.key`; auto-generated if missing)

macOS/Linux:
```bash
./relay --port 4001
./relay --port 4001 --key-path ./relay.key
./rendezvous --port 4002
```

Logging (macOS/Linux):
```bash
RUST_LOG=info ./relay --port 4001
RUST_LOG=info ./rendezvous --port 4002
```

Windows (PowerShell):
```powershell
./relay.exe --port 4001
$env:RUST_LOG = "info"; ./relay.exe --port 4001
./rendezvous.exe --port 4002
```

### Option B: From source
Prerequisite: Rust toolchain installed.

Relay (run inside `relay/`):
```bash
cd relay
cargo run -- --port 4001
cargo run -- --port 4001 --key-path ./relay.key
```

Rendezvous (run inside `rendezvous/`):
```bash
cd rendezvous
cargo run -- --port 4002
cargo run -- --port 4002 --key-path ./rendezvous.key
```

Logging (from source):
```bash
cd relay && RUST_LOG=info cargo run -- --port 4001
cd rendezvous && RUST_LOG=info cargo run -- --port 4002
```

Release builds (optional):
```bash
cd relay && cargo build --release
cd rendezvous && cargo build --release
```
