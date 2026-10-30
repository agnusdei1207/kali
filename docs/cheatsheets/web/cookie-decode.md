# 쿠키 디코딩 / 분석

## 개요

웹 서비스가 쿠키를 사용해 로그인 상태를 유지한다. 쿠키의 값은 URL 인코딩되어 있으므로,
원본 값을 복원해야 다음 요청에서 쓸 수 있는 계정 정보를 해석할 수 있다.

## 쿠키 문자열 읽기

응답 헤더의 `Set-Cookie` 또는 요청에 실려온 `Cookie` 값을 그대로 복사한다.

```text
Cookie: wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_45a7e4c82b517c5af328feabce4d0187=wpuser%7C1753668949%7FcPTwzE1cbFpF18C6ZZZnuwRE0D2eRXISGnrDPvbQcBv%7Cccf2b309c5881393194d94ea8fc1ff5c9b3a8324cfc1282e423f89ccc74ee070
```

## 디코딩 (Python)

```bash
python3 -c \"import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read()))\"
```

입력: `wpuser%7C1753668949%7FcPTwzE1cbFpF18C6ZZZnuwRE0D2eRXISGnrDPvbQcBv`

출력:

```text
wpuser|1753668949|cPTwzE1cbFpF18C6ZZZnuwRE0D2eRXISGnrDPvbQcBv
```

구분자 `|`를 기준으로 해석한다:

| 구분자 | 의미 |
|--------|------|
| `wpuser` | 사용자 이름 |
| `1753668949` | 마지막 로그인 시간(epoch) |
| 이후의 토큰 | 세션 식별자 |

## 전체 데코딩 스크립트

```python
import sys
import urllib.parse

cookie = sys.stdin.read().strip()
for part in cookie.split(';'):
    key, _, value = part.partition('=')
    print(key.strip(), '=>', urllib.parse.unquote(value))
```

## curl 로 재현

```bash
curl -i -L \\
  -H \"Cookie: wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_45a7e4c82b517c5af328feabce4d0187=wpuser%7C1753668949%7FcPTwzE1cbFpF18C6ZZZnuwRE0D2eRXISGnrDPvbQcBv%7Cccf2b309c5881393194d94ea8fc1ff5c9b3a8324cfc1282e423f89ccc74ee070\" \\
  -H \"User-Agent: Mozilla/5.0\" \\
  http://www.smol.thm/wp-admin/
```

## 활용

- 로그인 후 얻은 쿠키는 같은 세션으로 이어받을 때 재사용한다(쿠키 재사용).
- 세션 식별자가 포함된 토큰을 다른 사용자 계정으로 바꿔 시도하면 권한 상승 후보를 찾는다(IDOR/세션 변조).
