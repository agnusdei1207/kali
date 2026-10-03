# 보안 도구 치트시트 모음

침투테스트, 포렌식, 권한 상승 등에서 사용하는 도구들의 단계별 사용 가이드입니다.

## 폴더 구조

```
01-reconnaissance/      → 정보 수집 및 네트워크 스캔
02-vulnerability-analysis/ → 취약점 분석 및 악용
03-initial-access/      → 초기 접근 (크래킹, 쉘 획득)
04-privilege-escalation/  → 권한 상승
05-lateral-movement/    → 횡이동
06-post-exploitation/   → 후처리 및 포렌식
common/                 → 공통 도구 및 기본 명령어
```

## 새로운 형식 (Structured Cheatsheets)

최신 가이드들은 다음 구조를 따릅니다:

1. 설치 방법
2. 기본 개념
3. 빠른 시작 (단계별 3-5단계)
4. 실제 사용 시나리오 (2-4개)
5. 주요 옵션 (테이블)
6. 고급 사용법
7. 팁과 주의사항

이 형식을 사용하는 파일:
- `01-reconnaissance/network/nmap-structured.md`
- `03-initial-access/cracking/hydra/hydra-structured.md`

## 추천 학습 순서

### 1단계: 정보 수집 (reconnaissance)
- nmap-structured.md: 포트 스캔 및 서비스 발견
- ffuf.md: 웹 디렉토리/파라미터 파징
- dns.md: DNS 정보 수집

### 2단계: 취약점 분석 (vulnerability-analysis)
- curl/curl.md: 수동 웹 테스트
- web/sqli/sqlmap.md: SQL 인젝션
- web/file-inclusion/: 파일 포함 취약점

### 3단계: 초기 접근 (initial-access)
- cracking/hydra/hydra-structured.md: 로그인 크래킹
- cracking/hashcat/: 해시 크래킹
- shells/: 역쉘 및 바인드 쉘

### 4단계: 권한 상승 (privilege-escalation)
- linux/: Linux 권한 상승
- windows/: Windows 권한 상승

### 5단계: 횡이동 (lateral-movement)
- pivoting/: 프록시 및 터널링

### 6단계: 후처리 (post-exploitation)
- forensics/: 포렌식 도구

## 각 카테고리별 주요 도구

### 01-Reconnaissance

#### Active Directory
- bloodhound: AD 시각화
- crackmapexe: AD 정보 수집
- enum4linux: Linux/Samba 정보
- impacket: Windows RPC 공격
- kerbrute: Kerberos 열거

#### Network
- nmap: 포트 스캔 ⭐ (nmap-structured.md 추천)
- rustscan: 빠른 포트 스캔
- netcat: 네트워크 연결 테스트
- tcpdump: 패킷 캡처

#### OSINT / DNS
- dns.md: DNS 레코드 조회
- dnsrecon: DNS 열거
- Sublist3r: 서브도메인 발견

#### Web Surface
- ffuf: 파징 (디렉토리, 파라미터)
- gobuster: 디렉토리 발견
- wpscan: WordPress 스캔
- httpie: HTTP 요청 테스트

### 02-Vulnerability Analysis

#### CVE
- searchsploit: 공개 exploit 검색
- CVE-2024-21413: 특정 취약점 예시

#### Services (Database/FTP/SSH/SSL)
- mysql.md, postgres.md, mongodb.md: DB 취약점
- ftp.md: FTP 열거
- ssh_key_gen.md: SSH 키 생성
- openssl.md: SSL/TLS 분석

#### Web
- cookie-decode: 쿠키 디코딩
- file-upload: 파일 업로드 공격
- idor.md: IDOR 테스트
- url-encoding: URL 인코딩
- wordpress.md: WordPress 취약점

##### SQL Injection
- sqlmap: SQL 인젝션 자동 도구 ⭐
- sql_inject.md: 수동 SQL 인젝션
- blind_sql: 블라인드 SQL 인젝션

##### XSS
- xss.md: 크로스사이트 스크립팅

##### File Inclusion
- rfi.md: 원격 파일 포함
- null_byte.md: Null Byte 우회
- php_filter_chain_generator: PHP 필터 체인

##### SSRF
- ssrf.md: 서버사이드 요청 위조

### 03-Initial Access

#### Cracking
- rockyou: 비밀번호 리스트
- wordlists: 단어 리스트 모음

#### Hashcat
- hashcat.md: GPU 기반 해시 크래킹
- hashcat/mangling_rules.md: 규칙 기반 크래킹

#### Hydra
- hydra: 온라인 로그인 크래킹 ⭐ (hydra-structured.md 추천)
- hydra_practice.md: 실습

#### John the Ripper
- john_the_ripper.md: 해시 크래킹
- custom_rules.md: 커스텀 규칙

#### Metasploit Framework
- msf/install.md: 설치
- msf/exploit/: 익스플로잇 활용
- meterpreter/: Meterpreter 쉘 명령어
- msfvenom: Payload 생성

#### Shells
- reverse_shell.md: 역쉘 생성 ⭐
- bind-shell.md: 바인드 쉘
- reverse-shell/: 다양한 역쉘 언어별 예시
- shell-upgrade/: 쉘 업그레이드

### 04-Privilege Escalation

#### Linux
- sudo_privesc.md: SUDO 권한 상승
- suid.md: SUID 취약점
- sgid.md: SGID 취약점
- crontab: 크론 작업 악용
- linpeas: 자동 열거 도구

#### Windows
- windows_cheatsheet.md: Windows 기본
- cmd/: 명령 프롬프트 명령어
- powershell/: PowerShell 명령어

### 05-Lateral Movement

#### Pivoting
- mitmproxy: 프록시 및 MITM
- proxy: 터널링 및 포워딩

### 06-Post-Exploitation

#### Forensics
- volatility3: 메모리 포렌식
- rizin: 바이너리 분석

### common (공통)

#### Cryptography
- base64.md: Base64 인코딩
- ascii.md: ASCII 변환
- rsa.md: RSA 암호화
- dh.md: Diffie-Hellman

#### Linux CLI
- find, grep, sed, awk: 파일 검색/처리
- jq: JSON 파싱
- vim, nano: 텍스트 편집

#### Bash
- bash_syntax.md: 문법
- loop.md, if.md: 제어문
- brute_force.md: 브루트포스 스크립트

#### Scripts
- python_server.md: 간단한 HTTP 서버
- javascript_fetch: 웹 요청
- url_encode_decode: URL 인코딩/디코딩

## 사용 방법

각 도구마다:

1. 설치 방법 확인
2. 기본 개념 이해
3. 빠른 시작으로 처음 경험
4. 자신의 시나리오와 맞는 예시 찾기
5. 주요 옵션 참고하며 커스터마이징

## 팁

- 모든 파일은 마크다운(.md) 형식
- 명령어는 코드 블록으로 제공
- 각 옵션은 테이블 형식으로 정리
- 예시는 실제 사용 가능한 형태

## 추가 자료

- 공식 도구 문서 링크는 각 파일 하단에
- 관련 도구 링크도 참고 섹션에 포함
- 다른 가이드는 상단의 docs/README.md 참고

---

구조화된 새로운 형식으로 작성된 파일들부터 시작하면 이해하기 더 쉽습니다:
- nmap-structured.md
- hydra-structured.md

이 형식의 추가 작성을 진행 중입니다.
