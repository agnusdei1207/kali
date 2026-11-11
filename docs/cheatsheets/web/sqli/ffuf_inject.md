# ffuf_inject (ffuf 페이로드 주입)

> 무엇: ffuf로 URL의 `FUZZ` 위치에 워드리스트 값을 주입하고 상태 코드(`-mc`/`-fc`)로 필터링하는 HTTP 퍼징 기법
> 언제: 웹 열거 초기에 디렉터리·파일(`/admin`, `config.php`)을 찾거나, 발견한 파라미터(`?id=FUZZ`)에 값 목록을 넣어 반응 차이로 인젝션·취약 후보를 좁힐 때
> 조건: ffuf 설치(`apt install ffuf`)와 워드리스트(`/usr/share/wordlists/...`)가 필요하다. 결과가 너무 많으면 `-mc 200`으로 줄이고, 매칭된 URL은 직접 방문해 내용을 확인한다

## 개요

`ffuf`(Fuzz Faster U Fool)는 HTTP 파라미터에 페이로드를 주입해 반응을 살피는 퍼징 도구이다.
디렉터리 brute-force, 파라미터 값 주입, 취약점 확인에 쓴다.

## 설치

```bash
sudo apt update
sudo apt install ffuf -y
```

## 사용법

```bash
# 디렉터리 brute-force
ffuf -u http://target/FUZZ -w /usr/share/wordlists/dirb/common.txt

# 파라미터 값 주입
ffuf -u http://target/page.php?id=FUZZ -w /usr/share/wordlists/rockyou.txt
```

## 주요 옵션

| 옵션 | 설명 |
|------|------|
| `-u <url>` | 대상 URL (`FUZZ` 위치에 페이로드 삽입) |
| `-w <wordlist>` | 워드리스트 파일 |
| `-mc <code>` | 매칭할 상태 코드 (예: 200) |
| `-fc <code>` | 제외할 상태 코드 (예: 404) |
| `-o <file>` | 결과 파일 |
| `-of <format>` | 출력 형식 (json, csv, ejson, html, md) |

## 실전에서 하는 일

- 디렉터리(`/admin`, `/backup`, `/config`)를 먼저 찾는다.
- 찾은 디렉터리 안에 민감 파일(예: `config.php`, `.git/config`)이 있는지 확인한다.
- 매칭된 URL은 직접 방문해 내용을 확인한다.

## 팁

- 결과가 너무 많으면 `-mc 200`으로 200 응답만 필터링한다.
- 발견된 경로는 노트(05-progress-tracker)에 URL과 상태 코드와 함께 적는다.
