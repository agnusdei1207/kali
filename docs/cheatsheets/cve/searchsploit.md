# searchsploit

## 개요

`searchsploit`는 Exploit-DB의 취약점 목록을 검색하는 도구이다.
"이 서비스/버전에는 어떤 취약점이 공개되어 있는가"를 빠르게 알려준다.

## 설치

```bash
sudo apt update
sudo apt install exploitdb -y
```

## 주요 명령

```bash
searchsploit <키워드>          # 예: smartermail, eternalblue
searchsploit -s <service>    # 예: windows
searchsploit -m <module>     # 예: remote
searchsploit -cve <CVE>     # 예: CVE-2019-7214
searchsploit -u               # URL로부터 버전 자동 추론
```

## 파일 목록 조회

```bash
# 특정 파일 경로의 취약점만
searchsploit -f /path/to/file.py

# 카테고리별
searchsploit -t /windows/remote/
```

## 결과 해석

- 결과의 `Path`를 따라 해당 exploit를 실행한다.
- 실행 전 Exploit-DB에 있는 PoC가 원본임. 공개된 exploit를 그대로 쓴다.
- exploit 실행 후 target에 접속할 IP/포트를 해당 파일의 `HOST/PORT` 부분에 넣는다.

## 실전 예시

```bash
# 17001 포트의 MS .NET Remoting 서비스 (SmarterMail) 관련
searchsploit 17001
searchsploit -p smartermail
```

- 모든 시도는 합법적인 대상(본인 소유·허가받은 시스템)에서만 실행한다.
