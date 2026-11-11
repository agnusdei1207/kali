# Hashcat GPG / OpenPGP 해시 (-m 11700, 17010, 17020, 17030)

- GPG/OpenPGP 개인 키 패스프레이즈 크래킹 — 기본(-m 11700)과 SHA-256/384/512 변형(-m 17010/17020/17030), gpg2john으로 private.key에서 해시 추출
- 확보한 GPG 개인 키의 패스프레이즈를 알아내 키를 사용 가능한 상태로 만들 때
- gpg2john 추출 도구와 GPG 키 파일 — 키 암호는 보통 길고 복잡해 wordlist 품질이 결정적, cewl로 타겟 맞춤 단어 활용 고려

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