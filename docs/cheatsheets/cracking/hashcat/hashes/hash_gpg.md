# Hashcat GPG / OpenPGP 해시 (-m 11700, 17010, 17020, 17030)

## GPG (OpenPGP) (-m 11700)

```bash
hashcat -m 11700 -a 0 gpg.txt wordlist.txt
```

## GPG (SHA-256) (-m 17010)

```bash
hashcat -m 17010 -a 0 gpg_sha256.txt wordlist.txt
```

## GPG (SHA-384) (-m 17020)

```bash
hashcat -m 17020 -a 0 gpg_sha384.txt wordlist.txt
```

## GPG (SHA-512) (-m 17030)

```bash
hashcat -m 17030 -a 0 gpg_sha512.txt wordlist.txt
```

## 해시 추출

```bash
# gpg2john
gpg2john private.key > gpg.hash
```

## 팁

- GPG 키 암호는 보통 길고 복잡
- wordlist 품질이 결정적. cewl 활용 고려