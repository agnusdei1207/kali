# Hashcat SHA512 변형 (-m 1700, 1710, 1720, 1730, 1740, 1750, 1760)

## 기본 SHA512 (-m 1700)

```bash
hashcat -m 1700 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

## salt 포함 SHA512

```bash
# SHA512($pass.$salt) -m 1710
hashcat -m 1710 -a 0 hash.txt wordlist.txt

# SHA512($salt.$pass) -m 1720
hashcat -m 1720 -a 0 hash.txt wordlist.txt

# SHA512(unicode($pass).$salt) -m 1730
hashcat -m 1730 -a 0 hash.txt wordlist.txt

# SHA512($salt.unicode($pass)) -m 1740
hashcat -m 1740 -a 0 hash.txt wordlist.txt
```

## HMAC-SHA512

```bash
# HMAC-SHA512 (key = $pass) -m 1750
hashcat -m 1750 -a 0 hash.txt wordlist.txt

# HMAC-SHA512 (key = $salt) -m 1760
hashcat -m 1760 -a 0 hash.txt wordlist.txt
```

## SHA512 기반 해시

```bash
# sha512crypt (Linux) $6$ -m 1800
hashcat -m 1800 -a 0 shadow.txt wordlist.txt

# macOS v10.8+ (PBKDF2-SHA512) -m 7100
hashcat -m 7100 -a 0 hash.txt wordlist.txt

# GRUB 2 -m 7200
hashcat -m 7200 -a 0 hash.txt wordlist.txt

# Juniper/NetBSD sha1crypt? no. sha512crypt variants
```

## 팁

- $6$ (sha512crypt)는 salt 반복으로 매우 느림. 시간 제한 두고 시도