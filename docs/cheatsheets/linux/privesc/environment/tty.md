# tty / script

## 개요

리버스 쉘이 TTY 없이 동작하면, 대화형 명령을 다루기 어렵다. `script` 명령은 가상 터미널을 만들어 주는 도구이며, 이어서 확인한다.

## script — 가상 터미널 생성

```bash
script -c "bash -i" /tmp/session.log
```

- 이 명령을 실행하면 대상 측에서 bash가 떠오른다.
- `/tmp/session.log`에 대화 내용이 기록된다(증적으로 활용 가능).

## 확인

```bash
# 현재 세션의 TTY 확인
tty

# script로 만든 세션 로그를 읽는다
cat /tmp/session.log
```

## 활용

- 리버스 쉘에서 "입력이 안 먹히는" 문제를 재현할 때, `script`로 세션을 남긴다.
- TTY 업그레이드(`python3 -c 'import pty; pty.spawn("/bin/bash")'`)와 함께 기록한다.

## Windows

- Windows에는 `script`-와 동일한 개념이 없다. PowerShell 세션은 `rlwrap`/`Enter`로 그대로 사용한다(다른 문서 참고).
- 이 문서는 Linux 환경 기준이다.

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
- 해당 도구의 공식 문서는 --help를 참조하여 추가 옵션을 확인한다.
- 테스트 결과를 스크린샷으로 남겨 증적 자료로 활용한다.
- 유사한 취약점이 다른 머신에도 있는지 확인한다.
