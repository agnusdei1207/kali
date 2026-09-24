![](https://velog.velcdn.com/images/agnusdei1207/post/fe07846c-43ff-4976-baba-68a90f96104d/image.png)

## 1️⃣ 환경 준비

1. 브라우저 환경 변수 설정

   - **Linux/macOS**

     ```bash
     export SSLKEYLOGFILE=~/Documents/ssl-key.log
     firefox &
     ```

   - **Windows (PowerShell)**

     ```powershell
     set SSLKEYLOGFILE=C:\Users\<User>\ssl-key.log
     start firefox
     ```

   - 브라우저가 실행되면, TLS 세션 키가 자동으로 `ssl-key.log`에 기록됩니다.

2. 와이어샤크 설치 및 캡처 준비

   - 인터페이스 선택 후 HTTPS 트래픽을 포함할 네트워크 캡처 시작

---

## 2️⃣ 와이어샤크에서 TLS 키 적용

1. 메뉴에서 **Edit → Preferences → Protocols → TLS**
2. **(Pre)-Master-Secret log filename**에 `ssl-key.log` 경로 지정
3. `OK` 클릭 후, HTTPS 트래픽이 캡처된 pcap 파일을 열면 와이어샤크가 자동으로 복호화 시도

---

## 3️⃣ TLS 트래픽 복호화 확인

1. TLS 패킷을 클릭하면, 패킷 디테일 창에서 **Decrypted TLS** 섹션 확인 가능
2. HTTP 요청/응답 평문 확인

   - 로그인 폼 데이터, 쿠키, JSON, HTML 등
   - 예: `POST /login`의 `username`/`password` 평문

---

## 4️⃣ 유용한 디스플레이 필터

- HTTP 요청만 보기

  ```
  http
  ```

- 특정 문자열 포함 패킷 검색 (예: 로그인)

  ```
  http contains "로그인"
  ```

- 특정 IP 또는 포트 패킷

  ```
  ip.addr == 192.168.0.10
  tcp.port == 443
  ```

---

## 5️⃣ 실습 팁

- TLS 1.3 + Forward Secrecy 환경에서도 SSLKEYLOGFILE로 충분히 복호화 가능
- 실제 운영 환경에서는 SSLKEYLOGFILE **설정 금지** (보안 위험)
- 화이트햇 환경에서는 캡처 후 평문 분석으로 보안 테스트 가능
