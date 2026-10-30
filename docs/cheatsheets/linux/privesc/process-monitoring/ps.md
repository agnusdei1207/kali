# ps (프로세스 확인)

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

| 옵션        | 설명                               |
| ----------- | ---------------------------------- |
| `-p <PID>`  | 특정 프로세스만                    |
| `-a`        | 실행 중인 모든 프로세스            |
| `-u <user>` | 특정 사용자                        |
| `-x`        | 종료되지 않은 프로세스 포함        |
| `-o`        | 출력 컬럼 지정 (예: `pid,tty,cmd`) |

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
