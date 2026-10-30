# process (백그라운드 / foreground)

## 개요

리버스 쉘이 백그라운드로 실행되는 동안, 명령을 보내면 수신하지 못한다.
그때 `Ctrl+Z`로 백그라운드를 보내고 `fg`로 돌아온다.

## 흐름

```bash
# 실행 중인 작업을 백그라운드로 보낸다
Ctrl+Z

# 작업 목록 확인
jobs -l
jobs

# 포그라운드로 복원
fg %1
fg

# 백그라운드 작업 전체 종료
jobs -K
```

## kill

```bash
# 현재 백그라운드 작업 종료
sudo kill -9 <PID>

# 특정 이름으로
sudo pkill -9 openvpn
sudo killall -9 openvpn
```

## 주의

- `jobs -K`는 종료하지 못하는 백그라운드를 모두 종료한다.
- 리버스 쉘 안에서 `Ctrl+Z`를 누르면 리버스 셸 자체도 멈춘다. → `fg`로 복원.
- 증적을 남길 때, 이 시점에서 무엇을 시도했는지 함께 적는다.
