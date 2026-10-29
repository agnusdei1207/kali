```py
from mitmproxy import http

def request(flow: http.HTTPFlow):
    # 기존 X-Forwarded-For 제거 후 고정값으로 설정
    if "X-Forwarded-For" in flow.request.headers:
        del flow.request.headers["X-Forwarded-For"]
    flow.request.headers["X-Forwarded-For"] = "10.10.10.0"

    # (선택) 관련 헤더도 같이 고정하고 싶다면
    flow.request.headers["X-Real-IP"] = "10.10.10.0"

```

# 포트 8080에서 프록시 실행 (기본)

mitmproxy -s xff.py

# 포트 지정 (이전처럼 80)

mitmproxy -s xff.py -p 80

# 실행

curl -x http://127.0.0.1:80 targetIp
