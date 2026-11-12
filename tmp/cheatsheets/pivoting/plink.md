# PuTTY plink로 SSH 원격 실행·터널

- plink — PuTTY 패키지의 SSH 클라이언트 CLI. 비밀번호를 명령줄로 넘겨 비대화형 원격 명령 실행이 가능하고, -L/-R/-D로 터널을 제공한다.
- Windows 발판에서 SSH 원격 명령을 한 줄로 실행할 때, RDP 같은 내부 포트를 터널로 땡겨올 때, 배치 스크립트에서 프롬프트 없이 SSH를 쓸 때.
- Windows: workspace\windows\tools\putty\plink.exe (PuTTY 설치 후 PATH 권장). Kali는 apt install putty-tools.

## 기본 명령어 구조

```powershell
plink -ssh <계정>@<호스트> -P <포트> -pw <비밀번호> [명령]
```

- `-ssh`: SSH 프로토콜 지정.
- `-P`: 포트(대문자). `-pw`: 비밀번호.

## 원격 명령 실행 (Windows에서 Linux 대상)

```powershell
workspace\windows\tools\putty\plink.exe -ssh admin@10.10.14.5 -pw "P@ssw0rd" "id; uname -a"

workspace\windows\tools\putty\plink.exe -ssh admin@10.10.14.5 -pw "P@ssw0rd" "cat /etc/passwd"
```

- 첫 접속 시 호스트 키 확인 프롬프트가 뜬다. 스크립트에서는 미리 키를 받아둔다.

```powershell
echo y | workspace\windows\tools\putty\plink.exe -ssh admin@10.10.14.5 -pw "P@ssw0rd" exit
```

- 한 번 y로 수락하면 레지스트리에 키가 저장돼 이후 프롬프트가 사라진다.

## -batch (비대화형 강제)

```powershell
plink -batch -ssh admin@10.10.14.5 -pw "P@ssw0rd" "uptime"
```

- `-batch`: 모든 프롬프트를 금지. 호스트 키가 없으면 대기 대신 즉시 실패하므로 자동화에서 안전하다.

## SSH 터널

```powershell
# 로컬 포트포워드: 내부 10.0.0.10:3389를 내 PC 13389로
plink -ssh -L 13389:10.0.0.10:3389 admin@10.10.14.5 -pw "P@ssw0rd"

# 리모트 포트포워드: SSH 서버 쪽 9000을 내 PC 9000으로 노출
plink -ssh -R 9000:127.0.0.1:9000 admin@10.10.14.5 -pw "P@ssw0rd"

# 동적(SOCKS5): 내 PC 1080에 SOCKS5 프록시 생성
plink -ssh -D 1080 admin@10.10.14.5 -pw "P@ssw0rd"
```

- `-L 로컬포트:대상IP:대상포트`: SSH 서버가 대상 IP로 접속해 로컬 포트에 떠맡긴다.
- `-R 원격포트:내IP:내포트`: SSH 서버 쪽에 포트를 열어 내 쪽으로 되돌려 보낸다.
- `-D 포트`: SSH 서버를 경유하는 SOCKS5 프록시를 로컬에 만든다.

## 실전 예시

```powershell
# RDP 터널 후 접속
plink -ssh -L 13389:10.0.0.10:3389 admin@10.10.14.5 -pw "P@ssw0rd" -N
mstsc /v:127.0.0.1:13389
```

- `-N`: 명령 실행 없이 터널만 유지.

## 팁·트러블슈팅

1. -pw는 프로세스 목록에 남는다. 테스트 환경 외에는 키 인증(-i 키.ppk)을 쓴다.
2. Access denied가 나면 비밀번호의 특수문자 셸 이스케이프와 대소문자부터 확인한다.
3. Windows - Windows도 대상에 OpenSSH가 떠 있으면 동일하게 동작한다.
