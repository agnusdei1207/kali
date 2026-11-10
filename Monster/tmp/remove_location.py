# mitmproxy로 응답의 Location 헤더를 제거해 301 리다이렉트를 우회한다
# 사용: mitmproxy -s remove_location.py -p 80
from mitmproxy import http


def response(flow: http.HTTPFlow):
    if "Location" in flow.response.headers:
        del flow.response.headers["Location"]
