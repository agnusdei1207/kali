# CURL 치트 시트

## 기본 개념

curl은 URL을 사용하여 데이터를 전송하거나 받는 명령줄 도구입니다. 웹 요청을 테스트하고 API와 상호 작용하는 데 매우 유용합니다. OSCP 시험에서는 웹 취약점 테스트와 익스플로잇에 필수적인 도구입니다.

## 기본 사용법

### 기본 GET 요청

```bash
curl http://example.com
```

### 출력 파일에 저장

```bash
curl -o output.html http://example.com
```

### 진행 상황 표시하기

```bash
curl -# http://example.com
```

### 헤더 정보 포함하여 출력

```bash
curl -i http://example.com
```

### 헤더만 가져오기 (본문 제외)

```bash
curl -I http://example.com
```

### 리다이렉션 자동 따라가기

```bash
curl -L http://example.com
```

### 상세한 디버그 정보 출력

```bash
curl -v http://example.com
```

### 더 상세한 디버그 정보 (모든 통신 내용)

```bash
curl --trace output.txt http://example.com
```

## 인증 관련 옵션

### 기본 인증 (Basic Authentication)

```bash
curl -u username:password http://example.com
```

### Bearer 토큰 인증

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" http://example.com
```

### 클라이언트 인증서 사용

```bash
curl --cert certificate.pem --key private.key https://example.com
```

### 쿠키 사용

```bash
curl -b "name=value" http://example.com
```

### 쿠키 파일 사용

```bash
curl -b cookies.txt http://example.com
```

### 쿠키 저장

```bash
curl -c cookies.txt http://example.com
```

## 데이터 전송 (POST, PUT, DELETE 등)

### POST 요청 보내기

```bash
curl -X POST -d "param1=value1&param2=value2" http://example.com
```

### JSON 데이터로 POST 요청

```bash
curl -X POST -H "Content-Type: application/json" -d '{"key1":"value1", "key2":"value2"}' http://example.com
```

### 폼 데이터 전송

```bash
curl -X POST -F "name=user" -F "profile=@image.jpg" http://example.com/upload
```

### PUT 요청

```bash
curl -X PUT -d "param1=value1" http://example.com
```

### DELETE 요청

```bash
curl -X DELETE http://example.com/resource/123
```

## HTTP 헤더 조작

### 사용자 정의 헤더 추가

```bash
curl -H "User-Agent: Mozilla/5.0" -H "Accept-Language: ko-KR" http://example.com
```

### Content-Type 지정

```bash
curl -H "Content-Type: application/json" http://example.com
```

### Referer 헤더 설정

```bash
curl -H "Referer: http://google.com" http://example.com
```

## 프록시 사용

### HTTP 프록시 사용

```bash
curl -x http://proxy.example.com:8080 http://target.com
```

### SOCKS 프록시 사용

```bash
curl --socks5 127.0.0.1:9050 http://target.com
```

### Burp Suite와 함께 사용 (로컬 프록시)

```bash
curl -x http://127.0.0.1:8080 http://target.com
```

## SSL/TLS 관련 옵션

### SSL 인증서 검증 무시 (OSCP 환경에서 유용)

```bash
curl -k https://example.com
```

### 특정 SSL 버전 강제

```bash
curl --tlsv1.2 https://example.com
```

### SSL 인증서 정보 확인

```bash
curl -v --ssl https://example.com
```

## 타임아웃 및 재시도

### 연결 타임아웃 설정

```bash
curl --connect-timeout 10 http://example.com
```

### 전체 작업 타임아웃 설정

```bash
curl --max-time 30 http://example.com
```

### 재시도 설정

```bash
curl --retry 3 http://example.com
```

## 인코딩 및 디코딩

### URL 인코딩

curl 자체에는 URL 인코딩 기능이 내장되어 있지 않지만, 다른 도구와 함께 사용할 수 있습니다:

```bash
# Python을 사용한 URL 인코딩
encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('특수문자가 포함된 문자열'))")
curl "http://example.com/search?q=$encoded"
```

### URL 인코딩 (Bash에서)

```bash
# Bash를 사용한 URL 인코딩 함수
urlencode() {
  local string="${1}"
  local strlen=${#string}
  local encoded=""
  local pos c o

  for (( pos=0 ; pos<strlen ; pos++ )); do
     c=${string:$pos:1}
     case "$c" in
        [-_.~a-zA-Z0-9] ) o="${c}" ;;
        * )               printf -v o '%%%02x' "'$c"
     esac
     encoded+="${o}"
  done
  echo "${encoded}"
}

# 사용 예시
param=$(urlencode "특수문자 테스트 !@#$%^&*()")
curl "http://example.com/search?q=$param"
```

### URL 디코딩

```bash
# Python을 사용한 URL 디코딩
python3 -c "import urllib.parse; print(urllib.parse.unquote('URL%20%EC%9D%B8%EC%BD%94%EB%94%A9%20%ED%85%8C%EC%8A%A4%ED%8A%B8'))"
```

### Base64 인코딩 (curl과 함께 사용)

```bash
encoded=$(echo -n "username:password" | base64)
curl -H "Authorization: Basic $encoded" http://example.com
```

### Base64 디코딩

```bash
echo "dXNlcm5hbWU6cGFzc3dvcmQ=" | base64 -d
```

## 실전 활용 예시 (OSCP 관련)

### 취약점 테스트를 위한 명령어 인젝션 페이로드 전송

```bash
curl -X POST "http://vulnerable.com/exec?cmd=$(urlencode 'cat /etc/passwd')"
```

### SQL 인젝션 테스트

```bash
curl "http://vulnerable.com/page.php?id=1%27%20OR%201=1--"
```

### XSS 페이로드 테스트

```bash
curl "http://vulnerable.com/search?q=$(urlencode '<script>alert(1)</script>')"
```

### 파일 업로드 취약점 테스트

```bash
curl -X POST -F "file=@shell.php;filename=image.jpg;type=image/jpeg" http://vulnerable.com/upload
```

### JWT 토큰으로 요청 보내기

```bash
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." http://api.example.com
```

### CSRF 토큰 추출 후 사용

```bash
TOKEN=$(curl -s -c cookies.txt http://example.com/form | grep -o 'csrf_token" value="[^"]*' | cut -d'"' -f3)
curl -b cookies.txt -d "csrf_token=$TOKEN&username=admin&password=password" http://example.com/login
```

## 실전 팁 (OSCP)

1. **응답 처리**: `-s` 옵션으로 진행 표시줄을 숨기고 필요한 정보만 추출할 수 있습니다.

   ```bash
   curl -s http://example.com | grep "flag"
   ```

2. **자동화 스크립트에 활용**: 쉘 스크립트와 함께 curl을 사용해 반복적인 작업을 자동화합니다.

   ```bash
   for i in {1..100}; do
     curl -s "http://vulnerable.com/page.php?id=$i" | grep -q "confidential" && echo "Found at id=$i"
   done
   ```

3. **헤더 스푸핑**: 서버에 다른 클라이언트나 브라우저로 위장합니다.

   ```bash
   curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" http://example.com
   ```

4. **세션 유지**: `-b`와 `-c` 옵션을 함께 사용해 세션 쿠키를 유지합니다.

   ```bash
   curl -b cookies.txt -c cookies.txt http://example.com/authenticated_page
   ```

5. **취약한 헤더 테스트**: 보안 헤더를 조작해 취약점을 테스트합니다.

   ```bash
   curl -H "X-Forwarded-For: 127.0.0.1" http://example.com
   ```

6. **HTTP 메서드 테스트**: 허용되지 않은 HTTP 메서드를 테스트합니다.

   ```bash
   curl -X OPTIONS -v http://example.com
   ```

7. **404 탐지 우회**: `-f` 옵션으로 404 오류 시 출력을 숨길 수 있습니다.

   ```bash
   curl -f http://example.com/admin || echo "페이지가 존재하지 않습니다"
   ```

8. **CRLF 인젝션 테스트**:
   ```bash
   curl -v "http://example.com/%0D%0ASet-Cookie:%20malicious=1"
   ```

## 고급 URL 인코딩/디코딩 (Burp Suite 도구 활용)

OSCP 환경에서 Burp Suite를 사용할 수 있다면, Decoder 기능을 사용하여 복잡한 인코딩/디코딩 작업을 수행할 수 있습니다:

1. Burp Suite Decoder 탭으로 이동
2. 인코딩/디코딩할 텍스트 입력
3. "Encode as" 또는 "Decode as" 옵션 선택 (URL, HTML, Base64, ASCII Hex 등)
4. 결과 사용

특히, 다중 인코딩이 필요한 경우 Burp Suite의 Decoder가 매우 유용합니다.
