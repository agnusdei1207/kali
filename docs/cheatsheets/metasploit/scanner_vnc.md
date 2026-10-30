# vnc (vnc_login)

## 개요

Metasploit에 `auxiliary/scanner/vnc/vnc_login`이 있다. VNC 서비스의 비밀번호를 시도한다. 초기 침투 시 VNC 포트(또는 RDP 3389)가 열려 있고, 크리덴셜을 쓸 수 있는지 확인할 때 쓴다.

## 사용법

```bash
msfconsole
```

```text
msf6 > use auxiliary/scanner/vnc/vnc_login
msf6 > show options
```

## 주요 옵션

| 옵션 | 설명 |
|------|------|
| `RHOSTS` | 대상 IP |
| `RPORT` | VNC 포트 (default 5900) |
| `USER` | 계정 (여러 계정을 시도할 때) |

## 실전 예시

```text
msf6 > use auxiliary/scanner/vnc/vnc_login
msf6 > set RHOSTS 10.10.10.10
msf6 > run
```

## 주의

- 대상의 VNC 서비스가 비밀번호를 요구하는지 먼저 확인한다(서비스 버전).
- 계정 목록은 SecLists의 credentials wordlist를 섞어 쓴다(03-initial-access/cracking 참고).
- VNC 세션으로 접근하면 곧바로 Windows 권한 상승 단계(04-privilege-escalation)로 넘어간다.

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
