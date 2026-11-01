# python_pty (셸 안정화)

## 개요

리버스 쉘에 TTY(가상 터미널)를 붙여 주는 것이 "셸 안정화"다.
이 문서는 OSCP 체크포인트의 핵심 절차이다.

TTY가 필요한 이유:
- `su`, `sudo`는 비밀번호 입력을 위해 stdin이 TTY인지 검사한다. TTY가 없으면 프롬프트 없이 그냥 멈춘다.
- 방향키, history, Ctrl+C도 동작하지 않는다.

## 1. TTY 업그레이드

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

- `/bin/bash` 대신 `/bin/sh`도 가능하다.
- Windows 타깃에는 이 단계가 없다. PowerShell 셸은 pty 없이도 대화형으로 동작한다.

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
- Windows 타깃은 안정화가 필요 없다. 입력 편집이 불편하면 공격자에서 `rlwrap nc -lvnp <port>`로 감싼다. rlwrap은 공격자에 설치하는 도구다 → [../../common/lab-setup/rlwrap.md](../../common/lab-setup/rlwrap.md)
