# sshuttle로 SSH 서브넷 라우팅

- sshuttle — SSH 자격만 있으면(원격에 python3만 있으면) 원격 내부망 서브넷을 로컬 라우팅 테이블로 가져오는 poorman VPN. iptables로 트래픽을 SSH 터널로 보낸다.
- SSH 계정 하나로 내부 웹·DB·SMB 전체에 접근할 때, SOCKS 툴체인 없이 curl·nmap·브라우저를 그대로 쓰고 싶을 때, 내부 DNS 질의까지 터널로 보낼 때(--dns).
- 공격 호스트(Kali)는 root 권한 필요(iptables 조작), 대상 SSH 서버에 python3 필요. Kali는 apt install sshuttle.

## 기본 명령어 구조

```bash
sudo sshuttle -r <계정>@<SSH호스트> <서브넷> [서브넷2 ...]
```

- `-r`: 리모트 SSH 대상. 계정@호스트 형식이며 SSH 키 설정은 로컬 ssh 설정을 그대로 따른다.

## 기본 사용

```bash
sudo sshuttle -r user@10.10.14.5 10.0.0.0/24
sudo sshuttle -r user@10.10.14.5 10.0.0.0/24 172.16.0.0/16   # 여러 서브넷
sudo sshuttle -vr user@10.10.14.5 10.0.0.0/24                # -v 상세 로그
```

- 실행하면 클라이언트가 iptables 규칙을 걸고 SSH 연결을 유지한다. 프로세스를 끄면 규칙도 같이 정리된다.
- 이후 내부 IP를 직접 쓴다: curl http://10.0.0.10/, nmap 10.0.0.0/24 등.

## DNS 라우팅

```bash
sudo sshuttle --dns -r user@10.10.14.5 10.0.0.0/24
```

- `--dns`: DNS 질의도 터널로 보낸다. 내부 도메인(internal.corp) 풀이가 필요할 때 필수.

## 예외 서브넷

```bash
sudo sshuttle -r user@10.10.14.5 10.0.0.0/8 -x 10.10.14.5
```

- `-x`: 제외 서브넷. SSH 서버 자체 경로를 라우트에 넣어 루프가 나지 않게 한다(보통 자동 제외지만 명시 가능).

## chisel·ligolo와의 비교

- sshuttle: SSH 자격 필요, 대상에 python3 필요, 설정이 가장 간단. TCP 기반이라 ICMP는 안 간다.
- chisel: SSH 불필요. SOCKS5·포트포워드 중심이고 HTTP 채널이라 egress 제한 우회에 유리.
- ligolo-ng: TUN 기반. agent만 배포하면 되고 SYN 스캔 등도 자연스럽게 동작하며 Windows 발판에서 편하다.

## 실전 예시

```bash
# 내부망 전체 + DNS
sudo sshuttle --dns -r admin@10.10.14.5 10.0.0.0/8

# 내부 웹 접근
curl -u user:pass http://10.0.0.10/admin

# 포트 스캔
nmap -sT -Pn -p 445,3389 10.0.0.0/24
```

## 팁·트러블슈팅

1. 원격에 python3가 없으면 시작 직후 remote: python not found로 죽는다. 설치하거나 chisel로 전환한다.
2. UDP·ICMP는 기본 미지원. 필요하면 ligolo-ng 계열을 쓴다.
3. 규칙이 남아 라우팅이 이상해지면 sshuttle을 다시 실행했다가 정상 종료해 정리한다.
