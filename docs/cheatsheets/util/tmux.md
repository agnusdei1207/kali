# tmux

> 무엇: 터미널 멀티플렉서 tmux — SSH가 끊겨도 서버에 세션(리스너·스캔)을 살려 두고, 재접속 후 attach로 그대로 복귀하게 해 준다.
> 언제: nc 리스너를 상시 대기시키고 장시간 nmap·gobuster 스캔을 돌려 두는 실습·작업의 기본 환경으로.
> 조건: apt install tmux. 모든 조작은 Prefix(Ctrl+b) 조합이며 tmux new -s <이름>으로 만들고 attach -t로 복귀한다.

터미널 멀티플렉서. SSH 연결이 끊겨도 세션(리스너, 스캔)이 서버에서 계속 살아 있어서 재접속 후 그대로 복귀한다. 롸잇업 실습에서 리버스셸 리스너와 장시간 스캔을 띄워 두는 기본 작업 환경으로 쓴다.

## 설치

```bash
sudo apt install tmux
tmux -V
```

## 세션 관리

```bash
tmux new -s oscp          # 새 세션 생성 (이름: oscp)
tmux ls                   # 세션 목록
tmux attach -t oscp       # 해당 세션 복귀
tmux attach               # 세션이 하나면 바로 복귀
tmux kill-session -t oscp # 세션 종료
tmux kill-server          # 모든 세션 종료
```

- SSH가 끊겼다면 재접속 후 `tmux attach` 만 치면 된다. 세션 안의 리스너·스캔은 그대로 살아 있다.

## Prefix

- 모든 단축키는 `Ctrl+b` 를 먼저 누르고 조합키를 누른다. 아래에서 이것을 Prefix 라고 쓴다.
- `Prefix d` — detach. 세션은 뒤에서 살아 있고 터미널만 빠져나온다. 스캔 걸어 두고 나갈 때 쓴다.

## 윈도우·패널 조작

```text
윈도우 (탭)
c          새 윈도우
,          윈도우 이름 변경
n / p      다음 / 이전 윈도우
숫자       해당 번호 윈도우로 이동
w          윈도우 목록에서 선택
&          윈도우 닫기

패널 (분할 화면)
%          좌우 분할
"          상하 분할
방향키     패널 이동
z          현재 패널 전체 화면 토글 (긴 출력 확인 후 재압축)
x          현재 패널 닫기
Ctrl+방향키  패널 경계 크기 조절
```

## 스크롤·복사 (copy mode)

- `Prefix [` — copy mode 진입. 스크롤이 안 되는 리버스셸 출력, 스캔 결과를 올려 볼 때 쓴다.
- 방향키·PgUp 으로 스크롤, `q` 로 모드 종료.
- `Space` 로 선택 시작 → `Enter` 로 복사 → `Prefix ]` 로 붙여넣기. 복사는 tmux 내부 버퍼에만 들어가고 시스템 클립보드에는 안 들어간다.

## 설정 (~/.tmux.conf)

```conf
# 마우스: 휠 스크롤, 패널 클릭 전환, 경계 드래그
set -g mouse on

# 스크롤 히스토리 증가
set -g history-limit 100000

# Prefix 를 Ctrl+a 로 교체 (GNU screen 습관용, 선택)
unbind C-b
set -g prefix C-a
bind C-a send-prefix
```

- 적용: `tmux source-file ~/.tmux.conf` (기존 세션에도 즉시 적용)

## 실전 패턴

- 세션 하나에서 리스너와 스캔을 분리해서 운용한다.

```text
tmux new -s oscp
  윈도우0 : nc -lvnp 443 (리스너 상시 대기)
  Prefix c → 윈도우1 : nmap, gobuster 등 스캔 실행
  Prefix 0 → 셸 잡히면 즉시 리스너 화면으로 복귀
```

- SSH 끊김 → 재접속 → `tmux attach` 로 리스너·스캔 전부 복구.
- 라인 편집이 필요한 리스너는 패널 안에서 `rlwrap nc -lvnp 443` 로 실행한다. (tmux 와 rlwrap 은 역할이 다르다: tmux 는 세션 유지, rlwrap 은 셸 품질)

## 주의

- 같은 세션을 여러 터미널에서 attach 하면 화면이 서로 동기화되어 작아 보인다. 혼자 쓸 때는 `tmux attach -d` 로 기존 클라이언트를 분리하고 붙는다.
- 큰 터미널에서 detach 후 작은 터미널에서 attach 하면 vi/nano 등 전체 화면 프로그램이 깨져 보인다. 세션 크기는 클라이언트 중 가장 작은 것을 따라간다.
- detach 없이 SSH가 강제로 끊겨도 세션은 서버에 남는다. 재접속 후 attach 하면 된다.
- copy mode 의 복사 내용을 시스템 클립보드로 옮기려면 xclip 연동 설정이 따로 필요하다. 간단히는 copy mode 에서 텍스트를 본 뒤 터미널 자체 선택 복사(`Ctrl+Shift+C`)를 쓴다. → [클립보드 복사](clip.md)
