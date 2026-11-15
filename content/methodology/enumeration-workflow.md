---
title: "내 열거 워크플로 — 무엇을 돌리고 왜 돌리는지"
date: 2026-03-24
weight: 10
draft: false
tags: ["enumeration", "nmap", "methodology", "smb", "http"]
summary: "무엇을, 왜, 어떤 순서로 돌리는지. 열거 단계에서 시간을 아끼는 판단 기준."
---

45+ 박스를 풀고 정착한 열거 워크플로다. "올바른" 것이 아니라 시간 압박 속에서도 빠뜨리지 않으면서 실제로 동작하는 것이다.

## 두 단계 Nmap 접근

예전에는 큰 nmap 스캔 하나를 돌렸다. 시간 낭비였다. 이제 매번 두 단계로 한다.

### Pass 1 — 빠른 TCP 스캔

```bash
nmap -sC -sV -oN scans/initial.nmap $IP
```

상위 1000 포트를 친다. 30초 정도 걸린다. 전체 스캔이 도는 동안 즉시 작업할 수 있는 것을 준다.

### Pass 2 — 전체 포트 스캔 (백그라운드)

```bash
nmap -p- -sV -oN scans/allports.nmap $IP
```

다른 터미널에서 실행한다. 이상한 높은 포트에 숨어 있는 서비스를 잡는다 — 거의 항상 하나는 있다. 웹 앱이 8443 이나 50000 포트에서 돌고 있는데 45분이 지나서야 발견한 적이 있다.

### UDP 도 돌릴 때

```bash
nmap -sU --top-ports 50 -oN scans/udp.nmap $IP
```

상위 50 포트만. 전체 UDP 스캔은 영원히 걸리고 거의 보상이 없다. 중요한 포트:

- **53** — DNS (zone transfer)

- **161** — SNMP (community string = 무료 정보)

- **389** — LDAP

- **123** — NTP (때로는 도메인 열거에 유용)

**규칙:** AD 박스라면 항상 UDP 를 돌린다. SNMP 와 UDP DNS 가 foothold 를 준 적이 한두 번이 아니다.

---

## 서비스별 — 내가 실제로 확인하는 것

순서가 중요하다. foothold 를 줄 가능성이 높은 순으로 서비스를 훑는다.

### HTTP/HTTPS (80, 443, 8080, 8443)

웹이 거의 항상 공격 표면이다. 먼저 친다.

**즉시 확인:**

1. 사이트를 수동으로 브라우징. 모든 것을 읽는다. 소스 코드 확인.

2. `/robots.txt`, `/sitemap.xml` 확인

3. 기술 스택 식별 — Wappalyzer 또는 응답 헤더

```bash
whatweb http://$IP
```

**디렉터리 브루트포싱:**

```bash
feroxbuster -u http://$IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html -o scans/ferox.txt
```

이제 gobuster 대신 feroxbuster 를 쓴다. 기본적으로 재귀적이고, 더 빠르며, 출력이 더 좋다.

**확장자 의사결정 트리:**

- Linux 박스 → `-x php,txt,html,sh`

- Windows 박스 → `-x aspx,asp,txt,html,config`

- 프레임워크 식별됨 → 프레임워크별 확장자 추가 (`.jsp`, `.do` 등)

**내가 저지른 흔한 실수:**

- /etc/hosts 에 호스트명을 추가하지 않음. 가상 호스팅은 어디에나 있다. 어디서든 — 헤더, 페이지 내용, 인증서 — 도메인 이름을 보면 추가하고 다시 스캔한다.

- 한 개의 워드리스트만 스캔. `directory-list-2.3-medium` 이 아무것도 찾지 못하면 `raft-medium-words.txt` 를 시도한다. 다른 리스트가 다른 것을 잡는다.

- 403 을 무시함. 403 은 무언가가 *존재*한다는 뜻이다. 우회를 시도하고, 확장자를 추가하고, 그 경로에 대해 더 깊이 열거한다.

**서브도메인/vhost 열거:**

```bash
ffuf -u http://$IP -H "Host: FUZZ.domain.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <default_size>
```

`-fs` 플래그가 결정적이다. 기본 응답 크기를 필터링하지 않으면 false positive 에 빠진다.

---

### SMB (139, 445)

두 번째로 확인한다. SMB 는 정보를 줄줄이 흘린다.

```bash
# Null session 확인
smbclient -N -L //$IP/

# Enum4linux (시끄럽지만 철저함)
enum4linux -a $IP

# 나중에 자격 증명으로 공유 목록
smbmap -H $IP
smbmap -H $IP -u 'guest' -p ''
```

**내가 찾는 것:**

- **읽을 수 있는 공유** — 모든 것 다운로드. `smbget -R smb://$IP/sharename/`

- **쓸 수 있는 공유** — SCF 파일 공격, 페이로드 드롭 가능성

- **사용자 목록** — null session 이 동작하면 RID brute force

```bash
# 사용자명을 위한 RID brute force
crackmapexec smb $IP -u '' -p '' --rid-brute
```

**Gotcha:** `smbclient -N` 과 `smbmap` 은 null session 에 대해 다르게 동작한다. 하나가 실패하면 다른 것을 시도한다. smbclient 는 아무것도 보여주지 않는데 smbmap 이 `guest` / 빈 비밀번호로 공유를 나열하는 박스가 있었다.

---

### FTP (21)

빠른 확인. 유용하거나 아니거나.

```bash
# 익명 로그인
ftp $IP
# Username: anonymous
# Password: (빈 값 또는 아무거나)
```

**익명이 동작하면:**

- 모든 것 다운로드: `mget *`

- 업로드 가능한지 확인. 테스트 파일 업로드. HTTP 도 서빙 중이면 웹쉘 경로가 될 수 있다.

- 숨겨진 파일 확인: `ls -la`

**익명이 동작하지 않으면:** 넘어간다. 나중에 자격 증명으로 돌아온다.

---

### DNS (53)

AD 박스에서 매우 중요. standalone 에서는 덜.

```bash
# Zone transfer 시도
dig axfr @$IP domain.htb

# 역방향 조회
dig -x $IP @$IP

# 모든 레코드
dig any domain.htb @$IP
```

Zone transfer 는 실제 engagements 에서는 드물지만 HTB/OSCP 박스에서는 정기적으로 나온다. 항상 시도한다.

**DNS 를 통한 서브도메인 brute force:**

```bash
dnsenum --dnsserver $IP --enum -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt domain.htb
```

---

### LDAP (389, 636)

LDAP 이 열려 있으면 AD 박스다. 그에 맞게 행동한다.

```bash
# Anonymous bind
ldapsearch -x -H ldap://$IP -b "DC=domain,DC=htb"

# 도메인을 모를 때 naming contexts 먼저
ldapsearch -x -H ldap://$IP -s base namingcontexts
```

**LDAP 에서 원하는 것:**

- 전체 사용자 목록

- 그룹 멤버십

- description 필드 (관리자들이 비밀번호를 description 에 넣는 것을 좋아한다)

- 서비스 계정

```bash
# 모든 사용자 가져오기
ldapsearch -x -H ldap://$IP -b "DC=domain,DC=htb" '(objectClass=person)' sAMAccountName description memberOf
```

**Gotcha:** Anonymous bind 가 항상 데이터를 주는 것은 아니다. 어떤 DC 는 bind 는 허용하지만 아무것도 반환하지 않는다. 나중에 유효한 사용자로 시도한다.

---

### Kerberos (88)

Kerberos 가 열려 있으면 = AD 박스. 자격 증명 없이 즉시 할 두 가지.

**사용자 열거:**

```bash
kerbrute userenum -d domain.htb --dc $IP /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

이것은 brute forcing 처럼 시끄럽지 않다. 유효한 사용자에 대해 실패 로그온 이벤트를 생성하지 않는다. 사용자 목록을 만드는 데 좋다.

**AS-REP Roasting (자격 증명 불필요):**

```bash
impacket-GetNPUsers domain.htb/ -dc-ip $IP -usersfile users.txt -no-pass
```

계정에 "Kerberos preauthentication 필요 안 함" 이 설정되어 있으면 해시를 얻는다. 크랙한다.

---

### MSSQL (1433)

```bash
# 기본 자격 증명
impacket-mssqlclient sa:sa@$IP
impacket-mssqlclient sa:''@$IP

# 나중에 찾은 자격 증명으로
impacket-mssqlclient domain.htb/user:password@$IP -windows-auth
```

**들어가면:**

- `xp_cmdshell` 로 명령 실행 (활성화해야 할 수도)

- `xp_dirtree` 로 강제 인증 / 해시 캡처

- linked server 확인 — `EXEC sp_linkedservers`

```sql
-- xp_cmdshell 활성화
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

---

### SNMP (161/UDP)

범죄적으로 저평가된다. "public" community string 의 SNMP 는 *모든 것*을 덤프한다.

```bash
# Community string 확인
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt $IP

# MIB 트리 walk
snmpwalk -v2c -c public $IP 1.3.6.1
```

**유용한 OID:**

- `1.3.6.1.2.1.25.4.2.1.2` — 실행 중인 프로세스

- `1.3.6.1.4.1.77.1.2.25` — 사용자 계정

- `1.3.6.1.2.1.25.6.3.1.2` — 설치된 소프트웨어

전체 트리를 walk 하는 대신 특정 OID 로 `snmpwalk` 를 쓴다. 더 빠르고 노이즈가 적다.

**Gotcha:** SNMPv1/v2c 가 동작 중이면 community string 이 평문으로 전송된다. 기본값은 거의 항상 `public`. 하지만 `private`, `manager`, `internal` 도 시도한다.

---

### WinRM (5985, 5986)

자격 증명 없이는 할 수 있는 것이 거의 없지만 열려 있음을 기록한다. 자격 증명이 생기면:

```bash
evil-winrm -i $IP -u 'user' -p 'password'
```

포트 5985 가 열려 있고 유효한 자격 증명이 있으면 → 즉시 쉘. Windows 에서 측면 이동의 go-to.

---

### SSH (22)

자격 증명 없이는 열거할 것이 별로 없다. 버전을 기록하고 (때로는 OS 버전을 드러낸다) 넘어간다.

```bash
# Banner grab
nmap -sV -p22 $IP
```

찾은 자격 증명으로 돌아온다. 사용자명 재사용을 시도한다. 다른 서비스에서 찾은 키를 시도한다.

**한 가지:** 어디서든 — 웹 디렉터리, SMB 공유, FTP — 개인 SSH 키를 찾으면 즉시 아는 모든 사용자에 대해 시도한다.

---

## 실제 워크플로

박스의 첫 15분이 이렇게 생겼다:

1. **터미널 1:** 빠른 nmap 스캔 → 결과 즉시 작업 시작

2. **터미널 2:** 전체 포트 스캔이 백그라운드에서 실행 중

3. **터미널 3:** HTTP 발견 시 → 브라우저 열기, whatweb, feroxbuster 실행

4. **노트:** 모든 발견, 모든 사용자명, 모든 잠재적 자격 증명 기록

```fallback
Target: $IP
Hostname: ???
OS: ???
Domain: ???

Open Ports:
-

Users Found:
-

Credentials:
-

Interesting Findings:
-
```

이 러닝 노트를 계속 업데이트한다. 기본적으로 들린다. 가장 많은 시간을 절약해 주는 것이 이것이다.

---

## 더 파고들 것 vs. 넘어갈 것

이것은 가장 어려운 기술이고 아직 배우는 중이다.

**더 파고들 때:**

- 커스텀 웹 앱을 발견했을 때 (거의 확실히 취약점이 있다)

- 사용자명은 찾았지만 비밀번호가 없을 때 (password spraying 시간)

- 서비스가 부분 정보를 반환했을 때 (아마 더 있다)

- 자격 증명 한 세트가 있지만 쉘을 못 얻을 때 (모든 곳에 재사용)

**넘어갈 때:**

- 기본 페이지, 커스텀 콘텐츠 없음, 두 워드리스트 후에도 directory busting 이 아무것도 반환하지 않을 때

- 서비스가 인증을 요구하고 자격 증명이 전혀 없을 때

- 한 서비스에 30분 이상 썼는데 보여줄 것이 없을 때

**가장 큰 시간 낭비:** 열거를 끝내기 전에 뭔가를 익스플로잇하려는 것. 한 서비스를 통해 foothold 를 얻으려고 몇 시간을 태웠는데 실제 경로는 아직 스캔하지 않은 포트에 있었던 적이 있다.

모든 것을 먼저 열거한다. 익스플로잇은 그 다음. 매번. 이 규칙을 깨면 후회한다.

---

## 빠른 참조 — 포트별 액션

| 포트 | 서비스 | 첫 이동 |
| --- | --- | --- |
| 21 | FTP | 익명 로그인 |
| 22 | SSH | 버전 기록, 넘어감 |
| 25 | SMTP | 사용자 열거 (VRFY/EXPN) |
| 53 | DNS | Zone transfer |
| 80/443 | HTTP | 브라우징, 기술 스택, 디렉터리 브루트 |
| 88 | Kerberos | 사용자 열거, AS-REP Roast |
| 110/143 | POP3/IMAP | 기본 자격 증명 시도 |
| 135 | MSRPC | rpcclient null session |
| 139/445 | SMB | Null session, 공유 목록 |
| 161 | SNMP | Community string brute, walk |
| 389/636 | LDAP | Anonymous bind, 사용자 덤프 |
| 1433 | MSSQL | 기본 자격 증명 (sa:sa) |
| 3306 | MySQL | 기본 자격 증명 (root:root) |
| 5985 | WinRM | 자격 증명 필요 → evil-winrm |
| 5432 | PostgreSQL | 기본 자격 증명 (postgres:postgres) |
| 6379 | Redis | 인증 없음? → RCE |
| 8080 | HTTP Alt | 80 과 동일 |

---

이 워크플로는 완벽하지 않다. 뭔가를 가르쳐주는 박스를 풀 때마다 업데이트한다. 핵심 원칙은 바뀌지 않는다: **빠르게 스캔, 넓게 열거, 노트 작성, 전체 그림을 보기 전까지 익스플로잇하지 않는다.**

- [Enumeration](https://heretek.dev/tags/enumeration/)
- [Nmap](https://heretek.dev/tags/nmap/)
- [Methodology](https://heretek.dev/tags/methodology/)
- [Smb](https://heretek.dev/tags/smb/)
- [Http](https://heretek.dev/tags/http/)