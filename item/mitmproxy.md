## ✅ 1. `mitmproxy` 설치 (Ubuntu)

```bash
# 시스템 업데이트
sudo apt update

# mitmproxy 설치
sudo apt install mitmproxy -y
```

> 🔹 설치되면 `mitmproxy`, `mitmdump`, `mitmweb` 3가지 도구가 포함됨.

---

## ✅ 2. mitmproxy 실행 (프록시 서버 열기)

```bash
# 기본 프록시 포트(8080)로 인터랙티브 콘솔 실행
mitmproxy
```

> 🔹 프록시 주소: `127.0.0.1:8080`
> 🔹 요청이 들어오면 화면에 하나씩 쌓임. 방향키 ↑↓ 로 탐색, `Enter`로 상세 보기.

---

## ✅ 3. 클라이언트 프록시 설정

### 예: 브라우저에서 프록시 수동 설정

- 프록시 서버: `127.0.0.1`
- 포트: `8080`

---

## ✅ 4. HTTPS 요청을 보기 위한 인증서 설치

```bash
# mitmproxy 실행 후 브라우저에서 접속
http://mitm.it
```

1. 운영체제에 맞는 인증서 다운로드 (예: Linux, Android 등)
2. 브라우저 또는 시스템에 인증서 설치

   - Firefox: 설정 → 인증서 보기 → 가져오기 → mitmproxy-ca-cert.pem
   - 시스템 인증서 폴더에 설치할 수도 있음

> 🔹 이 과정을 거쳐야 HTTPS 트래픽도 복호화 가능

---

## ✅ 5. 요청 내용 확인하기 (예: 폼 데이터)

### 요청 발생시키기

```bash
# 예시: curl로 POST 요청
curl -x http://127.0.0.1:8080 -X POST http://example.com/login \
     -H "Content-Type: application/x-www-form-urlencoded" \
     --data "username=abc&password=1234"
```

### mitmproxy 조작 키

| 키      | 설명                |
| ------- | ------------------- |
| ↑↓      | 요청 목록 탐색      |
| `Enter` | 요청/응답 상세 보기 |
| `Tab`   | 요청/응답 전환      |
| `q`     | 뒤로 가기           |
| `Q`     | 종료                |

---

## ✅ 6. 요청을 `curl` 명령어로 복원하고 싶을 때

### 직접 복사해서 curl로 재현 예시:

```
POST http://example.com/login
Content-Type: application/x-www-form-urlencoded

username=abc&password=1234
```

→ curl 변환:

```bash
curl -X POST http://example.com/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "username=abc&password=1234"
```

---

## ✅ 7. 터미널 모드에서 로그만 보기 (GUI 없이)

```bash
mitmdump -v
```

> 🔹 TUI 없이 로그만 출력. 스크립트와 함께 자동화할 때 유용.

---

## ✅ 8. mitmproxy 스크립트로 요청 자동 출력하기 (선택)

### `log_request.py` 만들기:

```python
def request(flow):
    print(">>>", flow.request.method, flow.request.pretty_url)
    print(flow.request.headers)
    print(flow.request.get_text())  # 폼 데이터 등 body
```

### 실행:

```bash
mitmdump -s log_request.py
```

---

## ✅ 요약 명령어 모음

```bash
# 설치
sudo apt install mitmproxy -y

# mitmproxy 실행 (TUI 인터페이스)
mitmproxy

# 단순 로그 보기 (CLI)
mitmdump -v

# 요청 자동 출력용 스크립트 실행
mitmdump -s log_request.py

# 인증서 설치 주소 (브라우저에서 열기)
http://mitm.it
```
