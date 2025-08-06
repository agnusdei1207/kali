# httpie

---

## 1. 설치

```bash
sudo apt update
sudo apt install httpie
```

- `sudo apt update`: 패키지 목록 최신화 (필수)
- `sudo apt install httpie`: httpie 설치 (필수)

---

## 2. 기본 사용법

### 2-1. GET 요청

```bash
# 끝에 / 는 리다이렉트 대응
# curl -L
http http://target.com/

# self certificate 자체 인증서 쓰는 경우 사용
http --verify=no https://target.com/

```

- `http`: httpie 명령어 (필수)
- `http://target.com/`: 대상 URL (필수)

### 2-2. POST 요청

```bash
http POST http://target.com/login user=admin password=1234
```

- `POST`: HTTP 메소드 (필수)
- `user=admin password=1234`: 폼 데이터 (필수/선택)

### 2-3. 헤더 추가

```bash
http http://target.com/ X-Api-Key:abcd1234
```

- `X-Api-Key:abcd1234`: 커스텀 헤더 (선택)

### 2-4. JSON 데이터 전송

```bash
http POST http://target.com/api Content-Type:application/json user=admin password=1234
```

- `Content-Type:application/json`: 헤더 지정 (필수/선택)
- `user=admin password=1234`: 자동으로 JSON 변환

### 2-5. 쿠키 사용

```bash
http http://target.com/ Cookie:"sessionid=abcd1234"
```

- `Cookie:"..."`: 쿠키 직접 지정 (선택)

### 2-6. 응답 저장

```bash
http http://target.com/ > response.txt
```

- `> response.txt`: 응답을 파일로 저장 (선택, .txt 등 확장자)

---

## 3. 실전 옵션 조합 예시

### 3-1. GET + 헤더 + 쿠키 + 저장

```bash
http http://planning.htb/ X-Api-Key:abcd1234 Cookie:"sessionid=xyz" > result.html
```

### 3-2. POST + JSON + 헤더 + 쿠키 + 저장

```bash
http POST http://planning.htb/api/login Content-Type:application/json user=admin password=1234 Cookie:"grafana_session=abcd" > login.json
```

### 3-3. PUT + 헤더 + 파일 업로드 + 저장

```bash
http PUT http://planning.htb/upload X-Requested-With:XMLHttpRequest file@exploit.sh > upload_result.txt
```

### 3-4. DELETE + 헤더 + 쿠키

```bash
http DELETE http://planning.htb/api/item/1 Authorization:"Bearer token" Cookie:"sessionid=xyz"
```

### 3-5. 여러 옵션 동시 사용 (실전 조합)

```bash
http POST http://grafana.planning.htb/login Content-Type:application/json user=admin password=0D5oT70Fq13EvB5r X-Forwarded-For:127.0.0.1 Cookie:"grafana_session=abcd" > login_result.txt
```

### 3-6. 파일 다운로드 후 grep로 필터링

```bash
http http://planning.htb/secret.txt > secret.txt && grep password secret.txt
```

### 3-7. POST + 파일 업로드 + 추가 데이터

```bash
http -f POST http://planning.htb/upload file@exploit.php user=admin
```

### 3-8. 실전 API 공격 조합

```bash
http POST http://planning.htb/api/v1/users Content-Type:application/json Authorization:"Bearer token" name=admin password=1234 > api_result.json
```

---

## 4. 옵션 요약

- `http|https` (필수): 프로토콜 포함 URL
- `GET|POST|PUT|DELETE` (선택): HTTP 메소드
- `헤더:값` (선택): 커스텀 헤더
- `파라미터=값` (선택): 폼/JSON 데이터
- `Cookie:"..."` (선택): 쿠키 직접 지정
- `file@파일명` (선택): 파일 업로드 (.sh, .php 등)
- `> 파일명` (선택): 결과 저장 (.txt, .json 등)
- `-f` (선택): 폼 데이터 강제

---

## 5. 참고

- httpie는 Burp Suite 대체, API/웹 취약점 확인에 매우 유용
- 명령어는 최대한 간결하게, 옵션은 필요할 때만 추가
- 실전에서는 여러 옵션을 한 번에 조합해서 공격 흐름을 빠르게 테스트
