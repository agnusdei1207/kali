# ps (프로세스 확인)

- 실행 중 프로세스를 확인하는 ps의 옵션(-p, -a, -u, -x, -o)과 ps aux·ps -ef 실전 명령, kill·pkill 종료를 정리한 문서
- 권한 상승 열거에서 root가 돌리는 프로세스와 인자에 크레덴셜이 노출된 프로세스를 찾을 때, 그리고 현재 셸의 TTY·PPID를 확인할 때 쓴다
- 최소 설치 환경(도커 등)에서는 `apt install procps`가 필요할 수 있고, kill 계열은 PID·이름을 정확히 지정해 의도치 않은 종료를 피한다

## 개요

현재 실행 중인 프로세스와 쉘의 정보를 확인하는 명령. OSCP 실전에서 자주 쓰인다.

apt install procps

## 사용법

```bash
# 현재 쉘의 프로세스 정보
ps -p $$

# 현재 쉘의 TTY, 실행 시간, 명령어까지
ps -p $$ -o pid,ppid,tty,cmd
```

## 주요 옵션

- `-p <PID>`: 특정 프로세스만
- `-a`: 실행 중인 모든 프로세스
- `-u <user>`: 특정 사용자
- `-x`: 종료되지 않은 프로세스 포함
- `-o`: 출력 컬럼 지정 (예: `pid,tty,cmd`)

```bash
ps aux
ps aux | grep bash
ps -ef
ps -u root

tail -f /var/log/openvpn.log
```

pkill openvpn
pkill -9 openvpn
kill -9 4345
