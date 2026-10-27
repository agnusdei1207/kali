# wfuzz — 웹 퍼징 치트시트

> 웹 애플리케이션의 숨겨진 경로/파라미터/값을 브루트포스하는 Python 기반 퍼저.
> ffuf와 유사하나 FUZZ 키워드 + 페이로드(`-z`) 방식이 특징.

---

## 0. 설치

### Kali / Debian

```bash
sudo apt update && sudo apt install wfuzz -y
```

### pip (가상환경 권장)

```bash
pip install wfuzz
```

### 동작 확인

```bash
wfuzz --version
wfuzz -h
```

> ⚠️ wfuzz는 Python 2/3 호환 이슈가 있을 수 있습니다. Kali 기본 패키지 버전 사용을 권장합니다.

---

## 1. 기본 구조

```bash
wfuzz [옵션] -z payload,wordlist.txt URL/FUZZ
# 또는
wfuzz [옵션] -w wordlist.txt URL/FUZZ
```

- `FUZZ` : 페이로드가 주입될 위치 표시자
- `FUZ2Z`, `FUZ3Z` : 다중 페이로드 (2번째, 3번째)
- `-z payload,wordlist` : 페이로드 종류 + 소스 지정
- `-w wordlist` : `-z file,wordlist` 의 축약형

### 가장 단순한 예

```bash
wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
  http://target.com/FUZZ

wfuzz -H "X-Forwarded-For: 10.10.10.1" --sc 302 -u http://192.168.142.200/FUZZ.php -w /usr/share/wordlists/wfuzz/general/big.txt
```

---

## 2. 페이로드 종류 (`-z`)

| 페이로드   | 설명                 | 예시                       |
| ---------- | -------------------- | -------------------------- |
| `file`     | 파일에서 읽기        | `-z file,wordlist.txt`     |
| `list`     | 쉼표 구분 리스트     | `-z list,admin-guest-test` |
| `range`    | 숫자 범위            | `-z range,1-100`           |
| `hexrange` | 16진수 범위          | `-z hexrange,0-ff`         |
| `burp`     | Burp Intruder 리스트 | `-z burp,positions.txt`    |

### 다중 페이로드 (FUZ2Z)

```bash
wfuzz -z file,users.txt -z file,passwords.txt \
  -d "user=FUZZ&pass=FUZ2Z" http://target.com/login
```

---

## 3. 필터링 / 매칭

### 숨기기 (hide) — 노이즈 제거

| 옵션   | 기준                  | 예시                             |
| ------ | --------------------- | -------------------------------- |
| `--hc` | HTTP 상태 코드        | `--hc 404,403`                   |
| `--hl` | 응답 라인 수          | `--hl 12`                        |
| `--hw` | 응답 단어 수          | `--hw 5`                         |
| `--hs` | 응답 문자 수 / 정규식 | `--hs 1234` / `--hs "Not Found"` |

### 보이기 (show) — 매칭만 출력

| 옵션   | 기준             |
| ------ | ---------------- |
| `--sc` | 상태 코드        |
| `--sl` | 라인 수          |
| `--sw` | 단어 수          |
| `--ss` | 문자 수 / 정규식 |

```bash
# 404/403 제외, 200만 보고 싶을 때
wfuzz -w wordlist.txt --hc 404,403 --sc 200 http://target.com/FUZZ
```

---

## 4. HTTP 옵션

### 헤더

```bash
wfuzz -w wordlist.txt -H "User-Agent: Mozilla/5.0" \
  -H "X-Forwarded-For: 10.10.10.1" http://target.com/FUZZ
```

### 쿠키

```bash
wfuzz -w wordlist.txt -b "session=abc123; token=xyz" http://target.com/FUZZ
# 또는
wfuzz -w wordlist.txt --cookie "session=abc123" http://target.com/FUZZ
```

### 메서드 / POST 데이터

```bash
# POST 브루트포스
wfuzz -w passwords.txt -X POST \
  -d "username=admin&password=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  http://target.com/login

# JSON 바디
wfuzz -w wordlist.txt -X POST \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","pass":"FUZZ"}' \
  http://target.com/api/login
```

### 인증

```bash
wfuzz -w wordlist.txt --basic user:pass http://target.com/FUZZ
wfuzz -w wordlist.txt --ntlm DOMAIN\\user:pass http://target.com/FUZZ
```

---

## 5. 프록시 / 디버깅

```bash
# Burp 프록시 경유
wfuzz -w wordlist.txt -p 127.0.0.1:8080 http://target.com/FUZZ

# HTTPS + 프록시
wfuzz -w wordlist.txt -p 127.0.0.1:8080:HTTPS https://target.com/FUZZ

# 컬러 출력 (터미널)
wfuzz -c -w wordlist.txt http://target.com/FUZZ

# 상세 출력
wfuzz -v -w wordlist.txt http://target.com/FUZZ
```

---

## 6. 결과 저장

```bash
# CSV로 저장
wfuzz -w wordlist.txt -o csv -f results.csv http://target.com/FUZZ

# JSON 저장
wfuzz -w wordlist.txt -o json -f results.json http://target.com/FUZZ

# 화면 + 파일 동시 (tee)
wfuzz -c -w wordlist.txt http://target.com/FUZZ | tee results.txt
```

> `-o` 지원 포맷: `raw`, `json`, `csv`, `html` (버전에 따라 상이)

---

## 7. 실전 예시

### 7-1. 디렉토리 / 파일 브루트포스

```bash
wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  --hc 404 -t 50 http://target.com/FUZZ
```

### 7-2. 확장자 추가

```bash
wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -z list,php-txt-html-bak \
  http://target.com/FUZZ.FUZ2Z --hc 404
```

### 7-3. 가상 호스트 (서브도메인) 탐지

```bash
wfuzz -c -w /usr/share/seclists/Discovery/DNS/namelist.txt \
  -H "Host: FUZZ.target.com" --hc 404,403 \
  http://target.com
```

### 7-4. GET 파라미터 퍼징

```bash
wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  "http://target.com/index.php?FUZZ=test" --hl 12
```

### 7-5. LFI 페이로드 테스트

```bash
wfuzz -c -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt \
  "http://target.com/page.php?file=FUZZ" --hs "Warning"
```

### 7-6. 숫자 IDOR (range)

```bash
wfuzz -c -z range,1-1000 http://target.com/user/FUZZ --hc 404
```

### 7-7. X-Forwarded-For 우회 + 로그인 브루트포스

```bash
wfuzz -c -w /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  -X POST -d "user=admin&password=FUZZ" \
  -H "X-Forwarded-For: 10.10.10.0" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --hc 401,403 http://target.com/login.php
```

---

## 8. 성능 / 스레드

```bash
# 스레드 수 (기본 10)
wfuzz -t 50 -w wordlist.txt http://target.com/FUZZ

# 요청 간 지연 (초)
wfuzz -s 0.2 -w wordlist.txt http://target.com/FUZZ

# 재귀 스캔 (발견된 디렉토리 재귀)
wfuzz -R 2 -w wordlist.txt http://target.com/FUZZ
```

---

## 9. wfuzz vs ffuf 빠른 비교

| 항목          | wfuzz                            | ffuf              |
| ------------- | -------------------------------- | ----------------- |
| 언어          | Python                           | Go                |
| 속도          | 느림                             | 빠름              |
| 페이로드 문법 | `FUZZ`, `FUZ2Z`                  | `FUZZ`            |
| 필터링        | `--hc`, `--hl` 등                | `-fc`, `-fl` 등   |
| 저장          | `-o fmt -f file`                 | `-o file -of fmt` |
| 스크립팅      | Python 플러그인 지원             | 제한적            |
| 추천 상황     | 복잡한 페이로드/스크립트 필요 시 | 대량/고속 스캔    |

---

## 10. 자주 겪는 문제

| 문제             | 해결                                      |
| ---------------- | ----------------------------------------- |
| `FUZZ not found` | URL에 `FUZZ` 키워드 포함 확인             |
| 결과가 너무 많음 | `--hc 404` 등 필터 추가                   |
| SSL 인증서 오류  | `--no-ssl` (버전에 따라) 또는 프록시 경유 |
| 속도 느림        | `-t` 스레드 증가, 또는 ffuf로 전환        |
| Python 버전 충돌 | Kali 기본 패키지 사용, venv 격리          |

---

## 참고

- 공식: https://github.com/xmendez/wfuzz
- 워드리스트: `/usr/share/seclists/`, `/usr/share/wordlists/`
- 관련: [ffuf 치트시트](../01-reconnaissance/web-surface/ffuf.md)
