# handler / listener (exploit/multi/handler)

## 개요

payload를 만든 뒤, 대상이 접속해 셸을 만드는 역할을 `exploit/multi/handler`가 한다.

## 실행

```bash
msfconsole
```

```text
msf6 > use exploit/multi/handler
msf6 > show options
```

## 주요 옵션

| 옵션 | 설명 |
|------|------|
| `LPHOST` / `LHOST` | 공격자 IP (리버스 쉘을 기다리는 곳) |
| `LPORT` / `LPORT` | 공격자 포트 |
| `PAYLOAD` | 사용할 payload |
| `SESSION` | 이미 열린 세션에 연결 |

- `LPHOST`는 항상 tun0의 실제 IP로 적는다. `0.0.0.0`이 아닌 자기 자신의 주소.
- 포트는 4444, 1234 등으로 정한다 (기존 listener와 겹치지 않게).

## 실행 및 세션 관리

```bash
msf6 > exploit
# 세션이 생기면
msf6 > sessions -l
msf6 > sessions -i 1     # 접속
```

- `exploit`가 실패하면 `show options`로 `PAYLOAD`/`LPHOST`를 다시 확인한다.
- 세션이 떠오르지 않으면, 공격자 IP·포트·payload 조합을 다시 시도한다(보통 LHOST 오타).

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
