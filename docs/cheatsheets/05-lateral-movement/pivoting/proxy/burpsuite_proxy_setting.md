# BurpSuite 프록시 설정 (Proxy Setting)

> 참조 이미지: ![burpsuite proxy setting](https://github.com/user-attachments/assets/4f789695-4abe-4144-ac48-ca7b81ab6ae9)

## 1. BurpSuite 기본 프록시 리스너

- BurpSuite 실행 시 기본 프록시 리스너: `127.0.0.1:8080`
- 경로: `Proxy` → `Options` → `Proxy Listeners`
- 브라우저/도구의 프록시를 `127.0.0.1:8080`으로 지정하면 BurpSuite를 경유

```text
Browser/Tool  -->  BurpSuite (127.0.0.1:8080)  -->  Target
```

## 2. 브라우저 프록시 연결

- Firefox: Settings → Network Settings → Manual proxy → HTTP Proxy `127.0.0.1` Port `8080`
- 또는 BurpSuite 내장 브라우저(Chromium) 사용 (자동 연결)

## 3. HTTPS 인증서 (CA) 설치

- BurpSuite CA 인증서: `http://burp` (프록시 경유 시 다운로드)
- 브라우저에 CA 인증서 설치 → HTTPS 트래픽 복호화/인터셉트 가능

## 4. 업스트림 프록시 (Upstream Proxy) 연결

외부/내부 프록시(Squid 등)를 경유해야 할 때 BurpSuite에 업스트림 프록시 등록.

- 경로: `User options` → `Connections` → `Upstream Proxy Servers` → `Add`
- 설정 예 (Squid 경유):
  - Destination host: `*` (또는 특정 호스트)
  - Proxy host: `192.168.182.189`
  - Proxy port: `3128`

```text
Browser/Tool  -->  BurpSuite (127.0.0.1:8080)  -->  Squid (192.168.182.189:3128)  -->  Target
```

## 5. 인터셉트 (Intercept)

- `Proxy` → `Intercept` → `Intercept is on/off`
- 요청 가로채기/수정 후 `Forward`로 전송

## 6. 자주 쓰는 단축키

| 동작               | 단축키     |
| ------------------ | ---------- |
| 인터셉트 토글      | `Ctrl + T` |
| 요청 전송(Forward) | `Ctrl + F` |
| 드롭(Drop)         | `Ctrl + D` |

## 7. CLI/도구와 연동

```bash
# curl
curl -x http://127.0.0.1:8080 http://target

# proxychains (TCP)
proxychains curl http://target

# hydra (환경변수)
HTTP_PROXY=http://127.0.0.1:8080 hydra ...
```

## 참고

- BurpSuite Community/Professional 공통
- 업스트림 프록시 미지원 모듈(일부)은 `proxychains`로 대체
