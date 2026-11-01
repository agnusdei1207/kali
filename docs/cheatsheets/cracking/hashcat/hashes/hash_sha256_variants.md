# Hashcat SHA256 변형 (-m 1400, 1410, 1420, 1430, 1440, 1450, 1460)

## 기본 SHA256 (-m 1400)

```bash
hashcat -m 1400 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

## salt 포함 SHA256

```bash
# SHA256($pass.$salt) -m 1410
hashcat -m 1410 -a 0 hash.txt wordlist.txt

# SHA256($salt.$pass) -m 1420
hashcat -m 1420 -a 0 hash.txt wordlist.txt

# SHA256(unicode($pass).$salt) -m 1430
hashcat -m 1430 -a 0 hash.txt wordlist.txt

# SHA256($salt.unicode($pass)) -m 1440
hashcat -m 1440 -a 0 hash.txt wordlist.txt
```

## HMAC-SHA256

```bash
# HMAC-SHA256 (key = $pass) -m 1450
hashcat -m 1450 -a 0 hash.txt wordlist.txt

# HMAC-SHA256 (key = $salt) -m 1460
hashcat -m 1460 -a 0 hash.txt wordlist.txt
```

## SHA256 기반 해시

```bash
# sha256crypt (Unix) $5$ -m 7400
hashcat -m 7400 -a 0 hash.txt wordlist.txt

# Django (PBKDF2-SHA256) -m 10000
hashcat -m 10000 -a 0 hash.txt wordlist.txt

# PBKDF2-HMAC-SHA256 -m 10900
hashcat -m 10900 -a 0 hash.txt wordlist.txt

# HMAC-SHA256 (key = $pass) (PBKDF2) -m 12000? no, 12000 is PBKDF2-HMAC-SHA1
```

## 팁

- SHA256은 MD5보다 느리지만 GPU에서 여전히 빠름
- crypt 계열($5$)은 salt 반복 해싱으로 매우 느림