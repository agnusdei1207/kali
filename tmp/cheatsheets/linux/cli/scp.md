# scp — SSH로 파일 전송

- scp — SSH 채널 위에서 로컬과 원격 사이 파일을 복사하는 명령. 암호화된 연결 하나로 송수신이 끝나 별도 서버를 띄우지 않아도 된다.
- 익스플로잇·툴바이너리를 타깃에 올리거나, flag·덤프 파일·해시를 내려받을 때. OpenSSH 클라이언트가 있으면 어디서든 쓸 수 있다.
- 양쪽 모두 SSH 접근이 가능해야 하고 접속 계정의 사용자명·패스워드(또는 키)가 필요하다. Windows 타깃 경로(C:\Users\...)를 쓸 때는 이스케이프에 주의한다.

## 설치

```bash
sudo apt install openssh-client
```

## 송신 — 로컬에서 타깃으로

```bash
# scp <로컬파일> <계정>@<호스트>:<원격경로>
scp linpeas.sh jeff@192.168.80.200:/home/jeff/
scp PrintSpoofer64.exe jeff@192.168.80.200:'C:\Users\jeff\Desktop\'
```

- Windows 타깃(OpenSSH 서버)은 드라이브 루트가 `C:\` 기준이므로 절대경로는 `C:\Users\...` 형태로 쓴다. 작은따옴표로 감싸 백슬래시 이스케이프를 막는다.
- 대상이 디렉터리면 파일이 그 안에 복사되고, 파일명까지 쓰면 그 이름으로 저장된다.

## 수신 — 타깃에서 로컬로

```bash
# scp <계정>@<호스트>:<원격경로> <로컬경로>
scp jeff@192.168.80.200:C:\Users\jeff\Documents\passwords.txt .
scp jeff@192.168.80.200:C:\Users\jeff\Desktop\dump.txt /tmp/dump.txt
```

- 마지막 인자가 로컬 경로다. `.`는 현재 디렉터리로 내려받는다는 뜻.

## 디렉터리·복수 파일·옵션

```bash
# 디렉터리 통째로 (-r 필수)
scp -r tools/ jeff@192.168.80.200:/home/jeff/tools/
# 여러 파일 한 번에
scp a.txt b.txt jeff@192.168.80.200:/home/jeff/
# 다른 포트의 SSH (기본 22)
scp -P 2222 payload.txt jeff@192.168.80.200:/home/jeff/
# 개인키 지정
scp -i id_rsa dump.txt jeff@192.168.80.200:/tmp/
```

- `-P`(대문자)는 scp 전용 포트 옵션이고, ssh는 소문자 `-p`다. 혼동하기 쉽다.

## REMOTE HOST IDENTIFICATION HAS CHANGED 경고 해소

타깃을 재생성하면 호스트 키가 바뀌어 접속이 막힌다. 기존 기록을 지우고 다시 접속한다.

```bash
ssh-keygen -R 192.168.80.200
# /home/kali/.ssh/known_hosts 에서 해당 호스트 줄이 제거된다
scp payload.txt jeff@192.168.80.200:/home/jeff/
```

- 경고 문구에 "Offending ECDSA key ... is in known_hosts" 줄이 있는데, 이 IP(또는 `[IP]:포트`)를 `-R`로 넘기면 된다.

## 트러블슈팅

- Permission denied면 계정·패스워드 문제가 대부분이다. ssh로 같은 계정에 대화형 로그인이 되는지 먼저 확인한다.
- `not a regular file`이 나오면 디렉터리인데 `-r`을 안 붙인 경우다.
- Windows 타깃에서 `C:Users...`처럼 백슬래시가 사라졌으면 큰따옴표 대신 작은따옴표로 감쌌는지 확인한다.
- 연결이 바로 끊기면 scp 서브시스템이 비활성화된 Windows OpenSSH 설정일 수 있다. 이때는 SMB·HTTP 전송(powershell iwr, certutil)으로 전환한다.
