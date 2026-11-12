# Python requests HTTP 자동화

- requests — Python 표준 HTTP 클라이언트 라이브러리. GET/POST 전송, 헤더·쿠키·세션 유지, 프록시 연동을 몇 줄로 처리하므로 로그인 재현·토큰 발급·반복 테스트 자동화의 기본 도구다.
- Burp Suite를 경유하며 요청을 관찰해야 할 때(proxies), 자기서명 인증서 HTTPS에 요청을 보내야 할 때(verify=False), 반복 요청·세션 유지가 필요한 워크플로를 만들 때.
- python3와 requests 패키지 필요. venv에서는 pip install requests, 시스템 전역은 apt로 python3-requests를 설치한다.

## 설치

```bash
pip install requests                  # venv 안에서 권장
sudo apt install python3-requests     # apt 환경 전역 설치
python3 -m venv venv && source venv/bin/activate && pip install requests
```

- apt로 설치한 python3-requests는 venv에서 import되지 않는다. venv 안에서는 반드시 pip install로 설치한다.

## 기본 GET/POST

```python
import requests

r = requests.get("http://10.10.10.10/login", timeout=5)
print(r.status_code, r.text[:200])

r = requests.post("http://10.10.10.10/login",
                  data={"username": "admin", "password": "admin"},
                  timeout=5)
print(r.status_code, r.headers.get("Set-Cookie"))
```

- `data=`는 form 인코딩, `json=`은 JSON 바디로 보낸다. `headers=`로 User-Agent 등을 덮어쓴다.
- `timeout=`은 반드시 넣는다. 무한 대기는 자동화 스크립트의 흔한 실패 원인이다.

## 세션 유지

```python
s = requests.Session()
s.post("http://10.10.10.10/login", data={"username": "admin", "password": "admin"})
r = s.get("http://10.10.10.10/admin")   # 로그인 상태의 쿠키가 유지된다
```

- requests.Session은 쿠키와 커넥션을 재사용한다. 로그인 후 보호 페이지를 훑는 흐름은 Session으로 묶는다.

## Burp 프록시와 인증서 검증 끄기

```python
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
r = requests.get("https://10.10.10.10/api", proxies=proxies, verify=False)
```

- `proxies`: 요청을 Burp(127.0.0.1:8080)로 통과시켜 실제 전송 내용을 관찰·수정한다.
- `verify=False`: 자기서명 인증서 HTTPS에서 인증서 검증을 끈다. urllib3 경고를 끄려면 `import urllib3; urllib3.disable_warnings()`를 추가한다.

## 실전 예시

```python
import requests, urllib3
urllib3.disable_warnings()

url = "https://10.10.10.10/login"
s = requests.Session()
with open("users.txt") as f:
    for user in f.read().splitlines():
        r = s.post(url, data={"username": user, "password": "Test123!"},
                   proxies={"http": "http://127.0.0.1:8080",
                            "https": "http://127.0.0.1:8080"},
                   verify=False, timeout=5)
        if "Logout" in r.text:
            print("[+] valid:", user)
```

- 워드리스트를 한 줄씩 읽어 응답 차이(Logout 문자열 포함 여부)로 유효 계정을 판별하는 최소 스크립트 형태다.

## 팁·트러블슈팅

1. ConnectionError가 연속으로 나면 대상 포트나 프록시(8080)가 닫힌 것이다. `curl -x http://127.0.0.1:8080 http://target`으로 먼저 확인한다.
2. verify=False여도 SSLError가 나면 프록시가 TLS를 가로채지 못한 상태다. Burp의 인증서 설정을 확인한다.
3. 리다이렉션을 따라가지 않으려면 `allow_redirects=False`를 쓰고, 로그인 폼의 302 응답을 직접 검사할 때 유용하다.
