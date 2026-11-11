# Hashcat HMAC 해시

- hashcat HMAC 해시 크래킹 — HMAC-MD5/SHA1/SHA256/SHA512에서 키가 패스워드인지 salt인지에 따라 모드가 갈림(MD5 -m 50/60, SHA1 -m 150/160, SHA256 -m 1450/1460, SHA512 -m 1750/1760), TOTP -m 18100 포함
- API 서명·토큰 같은 HMAC 해시를 확보했을 때, 키와 메시지 위치를 구분해 모드를 골라야 할 때
- hashcat 설치, 해시 형식에서 키 위치($pass/$salt) 파악 — 모드가 키 위치에 따라 달라지므로 hashid·hashcat --example-hashes로 확인 필수

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