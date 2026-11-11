# openssl

> 무엇: OpenSSL s_client로 TLS 서비스에 직접 접속해 인증서 체인·CN/SAN·TLS 버전·검증 결과(Verify return code)를 확인하는 명령어 모음
> 언제: 443 등 TLS 포트를 발견했을 때 서비스 식별 단계로 인증서 정보를 뽑고, 구버전 TLS 지원 여부와 SNI 분기 가상 호스트를 확인할 때
> 조건: 공격자에 openssl 설치, 대상 포트 접근 가능, 가상 호스팅 대상은 -servername(SNI) 지정 필요(IP 접속 시 SNI를 빠뜨리면 인증서 오류가 난다)

```bash
sudo apt update
sudo apt install openssl
which openssl
openssl s_client -connect <호스트>:<포트>
openssl s_client -connect google.com:443
echo | openssl s_client -connect google.com:443
```

---

```bash
-connect <host:port>   # 접속할 대상
-servername <name>     # SNI 세팅 (가상 호스팅 시 필요)
-showcerts             # 서버에서 제공하는 전체 인증서 체인 보여줌
-tls1_2, -tls1_3       # 특정 TLS 버전으로 연결 시도
-CAfile <file>         # 인증서 검증용 CA 직접 지정
-quiet                 # 불필요한 출력 생략 (OpenSSL 3.0+)
-brief                 # 간략하게 보여줌
```

---

#### 1) 인증서 정보 텍스트로 보기

```bash
echo | openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -noout -text
```

* 인증서 본문(Base64)은 빼고 텍스트 정보만 출력
* CN, SAN, 만료일, 발급자, 공개키 정보 등 나옴

---

#### 2) SNI 분기 확인 (예: 여러 도메인이 같은 IP일 때)

```bash
openssl s_client -connect 10.0.0.1:443 -servername site1.example.com
```

* `site1.example.com` 도메인용 인증서가 나오는지 확인

---

#### 3) 서버가 TLS 1.2만 받는지 체크

```bash
openssl s_client -connect example.com:443 -tls1_2
```

* 연결되면 TLS 1.2 지원
* 실패하면 "handshake failure" 같은 에러 나옴

---

#### 4) 인증서 검증 코드 확인

```bash
openssl s_client -connect example.com:443 -CAfile /etc/ssl/certs/ca-certificates.crt
```

* 맨 마지막에 `Verify return code: 0 (ok)` → 검증 성공

---

### 📄 출력 내용 주요 필드

* `Certificate chain`: 인증서 체인 나열됨
* `Server certificate`: 실제 서버 인증서 내용
* `subject=`: CN, 조직명 등
* `issuer=`: 인증서 발급자
* `Verify return code`: 인증서 유효 여부 (0이면 정상)
* `Cipher`: 선택된 암호화 알고리즘
* `Protocol`: TLS 버전 (1.2, 1.3 등)

---

### ⛔ 빠질 수 있는 실수

* IP로 접속 시 `-servername` 빠뜨리면 인증서 오류 남 (가상 호스팅일 경우)
* `openssl x509`로 파싱하려면 `s_client` 출력에서 인증서만 뽑아야 함 → `echo |` + `2>/dev/null` 필요
* `Ctrl+C` 안 누르면 연결 대기 상태 지속됨

---

## 🧼 요약

```bash
# 가장 많이 쓰는 패턴
echo | openssl s_client -connect <IP또는도메인>:443 -servername <도메인> 2>/dev/null | openssl x509 -text -noout
```
---