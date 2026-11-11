# Hashcat 기타 해시

> 무엇: hashcat 마이너·기타 해시 모드 모음 — Ansible Vault(-m 16900), Password Safe(-m 9000/9100), eCryptfs(-m 12200), FileZilla Server(-m 15000), CRC32(-m 11500), PBKDF2 계열(-m 11900~12100), DPAPI masterkey(-m 15300/15900) 등
> 언제: 자주 나오지 않는 앱·시스템의 해시를 덤프했을 때, 해당 아티팩트가 어느 모드에 속하는지 여기서 검색할 때
> 조건: hashcat 설치 — 마이너 해시는 모드 번호·입력 형식이 제각각이라 hashcat --example-hashes 확인, hashid 1차 식별 후 시험 크래킹으로 확정

## Ansible Vault (-m 16900)

```bash
hashcat -m 16900 -a 0 ansible.txt wordlist.txt
```

## Password Safe v2 (-m 9000)

```bash
hashcat -m 9000 -a 0 pwsafe2.txt wordlist.txt
```

## Password Safe v3 (-m 9100)

```bash
hashcat -m 9100 -a 0 pwsafe3.txt wordlist.txt
```

## eCryptfs (-m 12200)

```bash
hashcat -m 12200 -a 0 ecryptfs.txt wordlist.txt
```

## FileZilla Server >= 0.9.55 (-m 15000)

```bash
hashcat -m 15000 -a 0 filezilla.txt wordlist.txt
```

## Tripcode (-m 16000)

```bash
hashcat -m 16000 -a 0 tripcode.txt wordlist.txt
```

## CRC32 (-m 11500)

```bash
hashcat -m 11500 -a 0 crc32.txt wordlist.txt
```

## SipHash (-m 10100)

```bash
hashcat -m 10100 -a 0 siphash.txt wordlist.txt
```

## RACF (-m 8500)

```bash
hashcat -m 8500 -a 0 racf.txt wordlist.txt
```

## PeopleSoft PS_TOKEN (-m 13500)

```bash
hashcat -m 13500 -a 0 peoplesoft.txt wordlist.txt
```

## PBKDF2 계열

```bash
# PBKDF2-HMAC-MD5 -m 11900
hashcat -m 11900 -a 0 hash.txt wordlist.txt

# PBKDF2-HMAC-SHA1 -m 12000
hashcat -m 12000 -a 0 hash.txt wordlist.txt

# PBKDF2-HMAC-SHA512 -m 12100
hashcat -m 12100 -a 0 hash.txt wordlist.txt
```

## SHA384 (-m 10800)

```bash
hashcat -m 10800 -a 0 hash.txt wordlist.txt
```

## scrypt (-m 8900)

```bash
hashcat -m 8900 -a 0 hash.txt wordlist.txt
```

## DES / 3DES (PT) (-m 14000, 14100)

```bash
hashcat -m 14000 -a 0 des.txt wordlist.txt
hashcat -m 14100 -a 0 3des.txt wordlist.txt
```

## Radmin2 (-m 9800, 9900)

```bash
hashcat -m 9800 -a 0 radmin2.txt wordlist.txt
hashcat -m 9900 -a 0 radmin2_lower.txt wordlist.txt
```

## CRAM-MD5 Dovecot (-m 16400)

```bash
hashcat -m 16400 -a 0 cram_md5.txt wordlist.txt
```

## DPAPI masterkey (-m 15300, 15900)

```bash
hashcat -m 15300 -a 0 dpapi_v1.txt wordlist.txt
hashcat -m 15900 -a 0 dpapi_v2.txt wordlist.txt
```

## Skip32 (-m 14900)

```bash
hashcat -m 14900 -a 0 skip32.txt wordlist.txt
```

## 팁

- 마이너 해시는 모드 번호 정확히 확인: `hashcat --example-hashes`
- 모드별 형식이 다름. hashid로 1차 식별 후 시험 크래킹으로 확정