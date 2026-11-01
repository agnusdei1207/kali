# Hashcat SHA1 변형 (-m 100, 110, 120, 130, 140, 150, 160)

## 기본 SHA1 (-m 100)

```bash
hashcat -m 100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

## salt 포함 SHA1

```bash
# SHA1($pass.$salt) -m 110
hashcat -m 110 -a 0 hash.txt wordlist.txt

# SHA1($salt.$pass) -m 120
hashcat -m 120 -a 0 hash.txt wordlist.txt

# SHA1(unicode($pass).$salt) -m 130
hashcat -m 130 -a 0 hash.txt wordlist.txt

# SHA1($salt.unicode($pass)) -m 140
hashcat -m 140 -a 0 hash.txt wordlist.txt
```

## HMAC-SHA1

```bash
# HMAC-SHA1 (key = $pass) -m 150
hashcat -m 150 -a 0 hash.txt wordlist.txt

# HMAC-SHA1 (key = $salt) -m 160
hashcat -m 160 -a 0 hash.txt wordlist.txt
```

## 기타 SHA1 기반

```bash
# PostgreSQL Challenge-Response (MD5) -m 11100
hashcat -m 11100 -a 0 hash.txt wordlist.txt

# MySQL Challenge-Response (SHA1) -m 11200
hashcat -m 11200 -a 0 hash.txt wordlist.txt

# SIP digest authentication (MD5) -m 11400
hashcat -m 11400 -a 0 hash.txt wordlist.txt

# IPMI2 RAKP HMAC-SHA1 -m 7300
hashcat -m 7300 -a 0 hash.txt wordlist.txt
```

## 팁

- 해시 포맷 확인: `hashcat --example-hashes | grep -i sha1`