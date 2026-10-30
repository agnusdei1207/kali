# python_pty (셸 안정화)

## 개요

리버스 쉘에 TTY(가상 터미널)를 붙여 주는 것이 "셸 안정화"다.
이 문서는 OSCP 체크포인트의 핵심 절차이다.

## 1. TTY 업그레이드

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

- `/bin/bash` 대신 `/bin/sh`도 가능하다.
- Windows 타깃이면 이 단계가 없다. `rlwrap nc`로 이미 안정된 상태다.

## 2. `stty` 설정

```bash
export TERM=xterm
stty raw -echo
```

## 3. 백그라운드 / 포그라운드 복원

1. 백그라운드로 보낸다: `Ctrl+Z`
2. 복원: `fg`

```bash
stty raw -echo; fg
```

## 확인

```bash
whoami
cd /tmp
# 방향키로 과거 명령을 되살리기
```

- 방향키, history, `sudo`의 비밀번호 프롬프트가 정상 동작하는지 확인한다.
- 이 단계가 어려우면(입력이 안 먹히면) `pty.spawn`만 다시 시도한다.
- Windows에서는 `rlwrap`이 기본 내장되어 있다. `rlwrap nc -lvnp <port>` 사용.
