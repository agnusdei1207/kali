# dump shell upgrade (TTY)

## 개요

리버스 쉘이 TTY(가상 터미널) 없이 동작하면, 방향키가 깨지고, `su` 같은 명령이 비밀번호 입력 없이 멈춘다.
OSCP 시험의 "셸 안정화"는 이 단계를 빠르게 통과하는지가 체크포인트가 된다.

## 원인

- `su`는 비밀번호 입력을 위해 `/dev/tty` 또는 stdin이 TTY인지 검사한다.
- 리버스 쉘은 기본적으로 TTY가 없으므로, 비밀번호 입력을 처리하지 못해 그냥 멈춘다.
- `sudo`도 마찬가지다.

## 1. Python으로 TTY 업그레이드

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

- 이 명령을 리버스 쉘 안에서 실행한다.
- 이후 대화형 셸처럼 동작한다(방향키, Ctrl+C, history 동작).

## 2. `stty` 오류 방지 (선택)

```bash
export TERM=xterm
```

## 3. 백그라운드 전환 후 복원

1. 백그라운드로 보낸다: `Ctrl+Z`
2. 복원: `fg` (또는 `stty raw -echo; fg`)

```bash
stty raw -echo; fg
```

## Windows에서는

- Windows 리버스 셸은 `rlwrap`이 기본 내장되어 있다(Windows 10).
- 그대로 사용한다: `rlwrap nc -lvnp 4444`.
- PowerShell 세션에서는 `Enter`로 명령을 주고, `exit`로 종료한다.

## 확인

- `whoami`가 정상 출력되는지, `cd` 후에도 터미널이 유지되는지 확인한다.
- 이 단계가 어려우면 증적(단계 6)에서 스크린샷으로 남긴다.
- 모든 시도는 합법적인 대상(본인 소유·허가받은 시스템)에서만 실행한다.
