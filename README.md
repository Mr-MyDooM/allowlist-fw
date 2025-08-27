# allowlist-fw

A Rust-based **firewall allowlist** app for Windows.  
It configures Windows Firewall so that **only specific domains are accessible** (Google Search, Google Drive, Indian Post, Amazon India) and **all other outbound traffic is blocked**.

---

## ℹ️ About this project

I built this tool for a **non-technical friend** who wanted to control office internet traffic without any advanced setup.  
It’s a simple, one-binary solution that runs on Windows and applies an allowlist of domains by resolving them to IPs and adding firewall rules.

---

## ⚠️ Warning

- This tool modifies **Windows Firewall rules** at the system level.  
- You **must run as Administrator**.  
- It will **block all outbound connections except the allowed domains**.  
- Test in a VM first and make sure you know how to restore firewall rules before using it on a production or personal machine.

---

## Features

- Resolves domain names to IPs dynamically (via `trust-dns-resolver`).  
- Adds outbound `netsh advfirewall` rules for those IPs.  
- Sets global outbound policy to **Block** so everything else is blocked.  
- CLI with subcommands:
  - `allowlist-fw run` → Apply allowlist firewall rules  
  - `allowlist-fw restore` → Restore firewall defaults (reset)  
- Designed for **Windows 10 / 11**.

---

## Allowed domains (default)

- `www.google.com`  
- `drive.google.com`  
- `www.indiapost.gov.in`  
- `www.amazon.in`

*(Edit `src/main.rs` to change or add more domains.)*

---

## Prerequisites

- Windows 10 / 11  
- Rust toolchain (stable) — install from https://www.rust-lang.org/tools/install  
- Run an Administrator PowerShell when applying rules

---

## Build

```powershell
git clone https://github.com/yourname/allowlist-fw.git
cd allowlist-fw
cargo build --release
```

The compiled binary will be:

```
target\release\allowlist-fw.exe
```

---

## Run

Open **PowerShell as Administrator** and run:

```powershell
# Apply firewall allowlist
.\target\release\allowlist-fw.exe run

# Restore firewall defaults (netsh reset)
.\target\release\allowlist-fw.exe restore
```

`run` will:
1. Resolve each allowed domain to its current A/AAAA records.
2. Create outbound firewall rules that allow traffic to those IPs.
3. Set the global outbound policy to `Block` (so everything else is blocked).

`restore` will:
- Reset firewall rules back to Windows defaults (or remove the rules created by the tool and set outbound to Allow — depending on implementation). Always check the implementation you used.

---

## Development notes

- Main crates used:
  - `trust-dns-resolver` — DNS resolution  
  - `clap` — CLI/subcommand parsing  
  - `tokio` — async runtime  
- Firewall changes are performed via the `netsh` CLI.
- Windows Firewall matches IPs — FQDN-based rules aren’t supported natively. For CDN-backed services (Google, Amazon), IP ranges may change frequently; consider re-running the tool on a schedule to refresh IPs.

---

## Safety & troubleshooting

- If you lose network connectivity, open an **Administrator PowerShell** and run:

```powershell
netsh advfirewall reset
```

- Alternatively, use the `restore` subcommand:
```powershell
.\target\release\allowlist-fw.exe restore
```

- Consider testing on a virtual machine first.

---

## License

MIT
