# Hashcat HMAC 해시

HMAC (Hash-based Message Authentication Code) 해시.

## HMAC-MD5

```bash
# key = $pass -m 50
hashcat -m 50 -a 0 hash.txt wordlist.txt

# key = $salt -m 60
hashcat -m 60 -a 0 hash.txt wordlist.txt
```

## HMAC-SHA1

```bash
# key = $pass -m 150
hashcat -m 150 -a 0 hash.txt wordlist.txt

# key = $salt -m 160
hashcat -m 160 -a 0 hash.txt wordlist.txt
```

## HMAC-SHA256

```bash
# key = $pass -m 1450
hashcat -m 1450 -a 0 hash.txt wordlist.txt

# key = $salt -m 1460
hashcat -m 1460 -a 0 hash.txt wordlist.txt
```

## HMAC-SHA512

```bash
# key = $pass -m 1750
hashcat -m 1750 -a 0 hash.txt wordlist.txt

# key = $salt -m 1760
hashcat -m 1760 -a 0 hash.txt wordlist.txt
```

## TOTP (HMAC-SHA1) (-m 18100)

```bash
hashcat -m 18100 -a 0 totp.txt wordlist.txt
```

## 팁

- HMAC은 키와 메시지 위치에 따라 모드가 다름
- hashid/hashcat --example-hashes로 정확한 모드 확인