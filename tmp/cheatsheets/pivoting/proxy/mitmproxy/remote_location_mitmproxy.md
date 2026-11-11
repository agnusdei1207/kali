- mitmproxy 스크립트로 응답의 Location 헤더를 삭제해 리다이렉트를 끊어버리는 설정 파일.
- 프록시 뒤에서 302 리다이렉트 때문에 원하는 응답을 직접 보지 못하고 넘어가 버릴 때.
- mitmproxy 설치 필요. mitmproxy -s <스크립트> -p <포트>로 띄우고 curl -x http://127.0.0.1:<포트>로 요청을 경유시킨다.

```py
from mitmproxy import http

def response(flow: http.HTTPFlow): # Location header remove
if "Location" in flow.response.headers:
del flow.response.headers["Location"]

```

# 포트 8080에서 프록시 실행 (기본)

mitmproxy -s xff.py

# 포트 지정 (이전처럼 80)

mitmproxy -s xff.py -p 80

# 실행

curl -x http://127.0.0.1:80 targetIp
