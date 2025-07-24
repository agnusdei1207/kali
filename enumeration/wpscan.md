## WPScan 실전 요약

### 1. 설치 및 준비

```bash
sudo apt update && sudo apt install wpscan ruby ruby-dev libcurl4-openssl-dev make gcc -y
```

### 2. 취약점 DB 업데이트

```bash
wpscan --version
wpscan --update
```

### 3. 기본 사용법

- 워드프레스 사이트 전체 스캔
  ```bash
  wpscan --url https://example.com
  ```
- 플러그인/테마 취약점 탐지
  ```bash
  wpscan --url https://example.com --enumerate p,t
  ```
  - `p`: 플러그인, `t`: 테마
- 브루트포스 로그인 시도
  ```bash
  wpscan --url https://example.com --usernames admin --passwords /usr/share/wordlists/rockyou.txt
  ```

### 4. 주요 옵션 정리

| 옵션                     | 설명                        |
| ------------------------ | --------------------------- |
| `--url <URL>`            | 대상 워드프레스 사이트 지정 |
| `--update`               | 취약점 DB 업데이트          |
| `--enumerate p`          | 플러그인 목록 스캔          |
| `--enumerate t`          | 테마 목록 스캔              |
| `--usernames <user>`     | 사용자 이름 지정            |
| `--passwords <파일경로>` | 비밀번호 리스트 지정        |

---
