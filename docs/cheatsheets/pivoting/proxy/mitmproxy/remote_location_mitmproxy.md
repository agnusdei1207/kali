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
