# dirsearch를 이용한 디렉토리·파일 브루트포싱

- dirsearch — Python으로 만든 웹 경로 스캐너. 워드리스트에 확장자를 붙여 디렉토리·파일을 찾고, 재귀 스캔·응답 필터·다양한 리포트 포맷을 기본 옵션으로 지원한다.
- ffuf·feroxbuster와 같은 자리지만, 재귀 스캔과 깔끔한 리포트(json/csv/html)가 한 번에 나온다는 점이 다르다.
- Python 3 환경에 python3 -m pip install dirsearch로 설치(또는 git clone 후 pip install -r requirements.txt)해야 한다. 인터넷이 막힌 환경이면 설치가 안 되므로 ffuf나 gobuster로 대체한다.

## 설치

```bash
python3 -m pip install dirsearch
# 또는
git clone https://github.com/maurosoria/dirsearch.git
cd dirsearch && python3 -m pip install -r requirements.txt
python3 dirsearch.py --help
```

## 기본 사용법

```bash
dirsearch -u http://10.10.10.1 -w /usr/share/seclists/Discovery/Web-Content/common.txt -e php,html -t 30
dirsearch -u https://example.com -e asp,aspx -r -o report --format html
```

## 주요 옵션

- `-u`: 대상 URL.
- `-w`: 워드리스트. 생략하면 내장 db/dicc.txt를 쓴다.
- `-e php,html`: 각 경로에 붙여볼 확장자. 지정하지 않으면 PHP 중심 기본 세트를 쓴다.
- `-t 30`: 스레드 수(기본 25).
- `-r`: 발견된 디렉토리 안을 재귀 스캔. --recursion-depth로 깊이 제한.
- `-x 404,500`: 제외할 상태 코드. -i는 통과시킬 상태 코드.
- `--format json -o report`: 출력 포맷(json, csv, html, txt)과 파일. --format은 -o와 함께 쓴다.
- `--full-url`: 결과를 전체 URL로 출력한다.

## 실전 예시

```bash
# 재귀 + 상태 코드 필터 + HTML 리포트
dirsearch -u http://10.10.10.1:8080 -w raft-medium-directories.txt -e php -r --recursion-depth 2 -x 404,403 -o ds_report --format html

# 기술 스택에 맞는 확장자 세트
dirsearch -u https://example.com -e aspx,asmx,ashx -t 20 -o iis_report --format txt
```

## ffuf·feroxbuster와 비교

- 설치가 간단하고 리포트 포맷이 다양해 결과 정리에 유리하다. 반면 속도는 Go·Rust 계열(feroxbuster, gobuster)이 빠르다.
- 파이프 연계·헤더 퍼징이 필요하면 ffuf, 자동 재귀 콘텐츠 발견이 필요하면 feroxbuster가 낫다.

## 팁과 트러블슈팅

- ModuleNotFoundError: requests가 나오면 의존성 설치가 안 된 것이다. pip install -r requirements.txt를 다시 실행한다.
- 인터넷이 안 되는 환경에서 pip 설치가 실패하면 ffuf나 gobuster로 같은 작업을 한다. 이 둘은 apt 설치형이라 오프라인에서도 동작한다.
- 대상이 429를 반환하기 시작하면 -t를 낮추고 --random-agent를 붙여본다. 응답이 전부 403으로 변하면 도구 탐지가 켜진 것이므로 스레드를 줄이고 속도를 늦춘다.
