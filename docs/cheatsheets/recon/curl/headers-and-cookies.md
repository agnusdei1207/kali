# curl 헤더 조작·쿠키·인증

## 헤더 조작

```bash
curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" http://target.com
curl -H "X-Forwarded-For: 127.0.0.1" http://target.com   # IP 기반 검증 우회 시도
curl -H "X-Real-IP: 127.0.0.1" http://target.com
```

## 기본 인증 / 토큰

```bash
curl -u user:pass http://target.com                                # Basic 인증
curl -H "Authorization: Bearer eyJh..." http://target.com          # JWT/토큰
curl -H "Authorization: Basic $(echo -n 'admin:password' | base64)" http://target.com
```

## 쿠키 저장·사용

```bash
curl -c cookie.txt http://target.com                # 응답 쿠키를 파일로 저장
curl -b cookie.txt http://target.com                # 저장된 쿠키 사용
curl -b cookie.txt -c cookie.txt http://target.com  # 세션을 유지하며 주고받기
curl -H "Cookie: sessionid=abcd" http://target.com  # 헤더로 직접 지정
```

## 세션 재사용 (쿠키 하이재킹)

```bash
curl -b "sessionid=STOLEN_SESSION_VALUE" http://target.com/admin
```

## CSRF 토큰 추출 후 로그인

```bash
TOKEN=$(curl -s -c cookie.txt http://target.com/form | grep -o 'csrf_token" value="[^"]*' | cut -d'"' -f3)
curl -b cookie.txt -d "csrf_token=$TOKEN&username=admin&password=password" http://target.com/login
```

## 쿠키 파일 (Netscape format)

`-c`로 저장한 파일의 한 줄은 탭으로 구분된 7개 필드다:

```text
grafana.planning.htb	FALSE	/	FALSE	1755096838	grafana_session_expiry	1752505433
#HttpOnly_grafana.planning.htb	FALSE	/	FALSE	1755096838	grafana_session	REDACTED
```

- 도메인 (앞에 `#HttpOnly_`가 붙으면 HttpOnly 쿠키)
- 서브도메인 포함 여부 (FALSE = 해당 도메인에만 유효)
- 경로 (`/` = 사이트 전체)
- HTTPS 전송 전용 여부 (Secure, FALSE = HTTP에서도 전송)
- 만료 시각 (Unix timestamp)
- 쿠키 이름
- 쿠키 값

## 실전: 로그인 세션으로 인증 페이지 접근

```bash
# 로그인하면서 세션 쿠키 저장
curl -i -X POST "http://www.smol.thm/wp-login.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "User-Agent: Mozilla/5.0" \
  --data "log=wpuser&pwd=REDACTED&rememberme=forever&wp-submit=Log+In&redirect_to=http://www.smol.thm/wp-admin/" \
  -c cookie.txt

# 저장된 쿠키(또는 탈취한 쿠키)로 admin 접근
curl -i -L \
  -H "Cookie: wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_45a7e4c82b517c5af328feabce4d0187=REDACTED" \
  -H "User-Agent: Mozilla/5.0" \
  http://www.smol.thm/wp-admin/
```
