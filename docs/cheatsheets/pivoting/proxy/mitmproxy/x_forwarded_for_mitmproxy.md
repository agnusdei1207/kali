> 무엇: mitmproxy 스크립트(xff.py)로 모든 요청의 X-Forwarded-For와 X-Real-IP를 고정값으로 덮어써 보내는 설정 파일.
> 언제: 서버가 X-Forwarded-For로 클라이언트 IP를 판단할 때, 특정 IP로 위장한 요청을 반복 테스트해야 할 때.
> 조건: mitmproxy 설치 필요. mitmproxy -s xff.py -p <포트> 실행 후 curl -x http://127.0.0.1:<포트>로 요청을 통과시킨다.

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
