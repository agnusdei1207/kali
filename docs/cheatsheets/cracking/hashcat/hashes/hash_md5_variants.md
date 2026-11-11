# Hashcat MD5 변형 (-m 0, 10, 20, 30, 40, 2600, 1400? no)

- hashcat MD5 계열 변형 모드 모음 — 기본 MD5(-m 0), salt 위치별 변형(MD5($pass.$salt) -m 10, MD5($salt.$pass) -m 20, unicode 변형 -m 30/40), HMAC-MD5(-m 50/60), Apache $apr1$(-m 1600)
- 웹 앱·레거시 시스템에서 MD5 형태 해시를 덤프했을 때, salt 위치·unicode 여부에 맞는 정확한 모드를 골라야 할 때
- hashcat 설치 — 변형이 많아 hashid와 hashcat --example-hashes로 모드 확인 필수, salt 포함 형식은 hash:salt 형태 해시 파일 필요

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