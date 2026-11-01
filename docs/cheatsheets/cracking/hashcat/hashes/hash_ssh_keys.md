# Hashcat SSH 키 해시 (-m 22911, 22921, 22931, 22941, 22951)

암호화된 SSH 개인키 크래킹.

## RSA (old format) (-m 22911)

```bash
hashcat -m 22911 -a 0 ssh_rsa.txt wordlist.txt
```

## DSA (-m 22921)

```bash
hashcat -m 22921 -a 0 ssh_dsa.txt wordlist.txt
```

## ECDSA (-m 22931)

```bash
hashcat -m 22931 -a 0 ssh_ecdsa.txt wordlist.txt
```

## Ed25519 (-m 22941)

```bash
hashcat -m 22941 -a 0 ssh_ed25519.txt wordlist.txt
```

## Putty (-m 22931? / 22951)

```bash
hashcat -m 22951 -a 0 putty.txt wordlist.txt
```

## 해시 추출

```bash
# ssh2john
ssh2john id_rsa > ssh.hash
# 또는 putty2john
putty2john key.ppk > putty.hash
```

## 팁

- 키 파일 권한 확인: `chmod 600 id_rsa`
- Ed25519 키는 암호화 시 PBKDF2로 느림
- wordlist + 규칙 조합이 효과적