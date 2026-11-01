# Hashcat MD5 변형 (-m 0, 10, 20, 30, 40, 2600, 1400? no)

MD5 계열 해시 모드 모음.

## 기본 MD5 (-m 0)

```bash
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

## salt 포함 MD5

```bash
# MD5($pass.$salt) -m 10
hashcat -m 10 -a 0 hash.txt wordlist.txt

# MD5($salt.$pass) -m 20
hashcat -m 20 -a 0 hash.txt wordlist.txt

# MD5(unicode($pass).$salt) -m 30
hashcat -m 30 -a 0 hash.txt wordlist.txt

# MD5($salt.unicode($pass)) -m 40
hashcat -m 40 -a 0 hash.txt wordlist.txt
```

## md5(md5($pass).$salt) -m 2600

별도 파일로 분리됨: `hash_2600_md5_double_salt.md` 참조.

## HMAC-MD5

```bash
# HMAC-MD5 (key = $pass) -m 50
hashcat -m 50 -a 0 hash.txt wordlist.txt

# HMAC-MD5 (key = $salt) -m 60
hashcat -m 60 -a 0 hash.txt wordlist.txt
```

## Apache MD5 ($apr1$) -m 1600

```bash
hashcat -m 1600 -a 0 hash.txt wordlist.txt
```

## 팁

- hashid로 정확한 모드 확인: `hashid hash.txt`
- 예제 해시로 형식 확인: `hashcat --example-hashes | grep -i md5`