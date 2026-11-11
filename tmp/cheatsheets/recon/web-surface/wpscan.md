# wpscan

- wpscan — WordPress 전용 스캐너. 코어·플러그인·테마 취약점 열거(--enumerate p,t)와 사용자 열거 후 패스워드 브루트포스까지 수행한다.
- whatweb 등으로 대상이 WordPress임이 확인됐을 때 바로 투입해 플러그인 취약점과 로그인 계정을 찾는다.
- apt 설치와 ruby 의존성이 필요하고, 최신 취약점 DB는 --update와 API 토큰(wpscan.com 무료 발급, --api-token)으로 열린다.

## WPScan 실전 요약

### 1. 설치 및 준비

```bash
sudo apt update && sudo apt install wpscan ruby ruby-dev libcurl4-openssl-dev make gcc -y
```

### 2. 주요 옵션 정리

| 옵션                     | 설명                        |
| ------------------------ | --------------------------- |
| `--url <URL>`            | 대상 워드프레스 사이트 지정 |
| `--update`               | 취약점 DB 업데이트          |
| `--enumerate p`          | 플러그인 목록 스캔          |
| `--enumerate t`          | 테마 목록 스캔              |
| `--usernames <user>`     | 사용자 이름 지정            |
| `--passwords <파일경로>` | 비밀번호 리스트 지정        |

| `--api-token <토큰>` | WPScan 공식 DB 연동(최신 취약점 정보) |

### 3. 취약점 DB 업데이트

```bash
wpscan --version
wpscan --update
```

### 4. 기본 사용법

#### 워드프레스 사이트 전체 스캔

```bash
wpscan --url https://example.com
```

#### 플러그인/테마 취약점 탐지

```bash
wpscan --url https://example.com --enumerate p,t
```

- `p`: 플러그인, `t`: 테마
#### 브루트포스 로그인 시도

```bash
wpscan --url https://example.com --usernames admin --passwords /usr/share/wordlists/rockyou.txt
```

#### 공식 취약점 DB 연동(더 많은 최신 정보)

```bash
# --ignore-main-redirect 리디렉션 무시
wpscan --url https://example.com --api-token <API토큰> --ignore-main-redirect
```

API 토큰 발급 방법

1. https://wpscan.com/user/register 접속
2. 이메일로 회원가입 후 로그인
3. 대시보드에서 API Token 복사
4. 명령어에 --api-token <복사한\_토큰> 추가

- 토큰 없으면 일부 정보 제한됨

---
