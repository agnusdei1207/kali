# BurpSuite 프록시 설정 (직관적인 설명)

BurpSuite는 웹 요청/응답을 중간에 가로채서 보고 수정할 수 있는 도구입니다.  
브라우저나 도구의 트래픽을 BurpSuite를 지나가게 하면 모든 HTTP/HTTPS 트래픽을 확인하고 조작할 수 있습니다.

---

## 전체 흐름도

```
브라우저/도구 ──→ BurpSuite (127.0.0.1:8080) ──→ 대상 서버
```

---

## 1단계: BurpSuite 프록시 리스너 확인

BurpSuite를 켰을 때 기본 프록시 리스너가 열려 있어야 트래픽을 받을 수 있습니다.

- 메뉴 경로: `Proxy` → `Options` → `Proxy Listeners`
- 기본 주소: `127.0.0.1:8080`
- 상태가 `Running`이어야 함 (포트는 기본값 8080을 쓰는 게 가장 편함)

> 포트를 바꾸고 싶으면 리스너를 편집해서 변경할 수 있지만, 기본값을 권장합니다.

---

## 2단계: 브라우저를 BurpSuite에 연결

브라우저의 트래픽을 BurpSuite로 보내려면 프록시 설정을 해야 합니다.

### Firefox (가장 쉬움, 추천)

1. Firefox 우측 상단 `≡` → `설정` → `네트워크 설정`
2. `수동 프록시 구성` 선택
3. HTTP 프록시: `127.0.0.1`, 포트: `8080`
4. `이 프록시를 모든 프로토콜에 사용` 체크
5. `확인`

### Chrome / Edge

시스템 프록시를 사용하므로 확장 프로그램(예: Proxy SwitchyOmega)을 쓰거나, 실행 시 옵션을 줍니다.

```bash
# Chrome을 프록시와 함께 실행 (Windows 예시)
chrome.exe --proxy-server="http://127.0.0.1:8080"
```

### BurpSuite 내장 브라우저 (설정不要)

BurpSuite에 포함된 Chromium 브라우저를 쓰면 프록시 설정이 자동으로 되어 있습니다. 별도 설정 없이 바로 사용할 수 있습니다.

---

## 3단계: HTTPS 인증서 설치 (중요!)

HTTPS 사이트를 보려면 브라우저에 BurpSuite의 CA 인증서를 설치해야 합니다.  
설치하지 않으면 HTTPS 접속 시 인증서 오류가 납니다.

1. 브라우저에서 `http://burp` 접속 (반드시 BurpSuite 프록시를 경유해야 함)
2. `CA Certificate` 다운로드 (`cacert.der` 또는 `.cer`)
3. 브라우저 인증서 저장소에 설치 → 신뢰할 수 있는 루트 인증서로 등록

- Firefox: `설정` → `개인정보 및 보안` → `인증서 보기` → 기관 인증서 → 가져오기 → `이 CA를 웹 사이트 식별에 신뢰` 체크
- Chrome / Edge: 시스템 인증서에 가져오기

---

## 4단계: 인터셉트 켜고 테스트

- `Proxy` → `Intercept` → `Intercept is on`
- 브라우저로 사이트 접속 → BurpSuite `HTTP history`에 요청이 표시됨
- 요청 클릭 → 헤더/본문 확인 및 수정 가능
- `Forward`로 전송, `Drop`으로 버림

---

## 5단계: 업스트림 프록시 연결 (선택)

만약 대상에 가기 전에 또 다른 프록시(Squid 등)를 거쳐야 한다면:

- 메뉴: `User options` → `Connections` → `Upstream Proxy Servers` → `Add`
- 예시 (Squid): Proxy host `192.168.182.189`, Proxy port `3128`

```
브라우저 ──→ BurpSuite (8080) ──→ Squid (3128) ──→ 대상 서버
```

---

## 6단계: curl 등 CLI 도구 연동

```bash
# curl을 BurpSuite 프록시로 보내기
curl -x http://127.0.0.1:8080 http://target.com

# HTTPS는 인증서 오류를 무시하려면 -k 추가
curl -k -x http://127.0.0.1:8080 https://target.com
```

---

## 자주 쓰는 단축키

| 동작                | 단축키     |
| ------------------- | ---------- |
| 인터셉트 켬 / 끔    | `Ctrl + T` |
| 요청 전송 (Forward) | `Ctrl + F` |
| 요청 버림 (Drop)    | `Ctrl + D` |

---

## 잘 안 될 때 체크리스트

| 문제                       | 확인할 것                                      |
| -------------------------- | ---------------------------------------------- |
| BurpSuite에 요청이 안 보임 | 브라우저 프록시가 `127.0.0.1:8080` 맞는지 확인 |
| HTTPS 사이트 접속 불가     | BurpSuite CA 인증서 설치 여부 확인             |
| 인터셉트가 안 켜짐         | `Proxy` → `Intercept` → `Intercept is on` 확인 |
| 대상 서버 연결 실패        | 업스트림 프록시 설정이 필요한지 확인           |

---

> 참고: BurpSuite Community / Professional 공통으로 적용됩니다.  
> 업스트림 프록시를 지원하지 않는 일부 모듈은 `proxychains`로 대체할 수 있습니다.
