# Hashcat NTLM (-m 1000)

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