# Hashcat 패스워드 매니저 해시

KeePass, 1Password, LastPass, Bitwarden 등.

## KeePass 1/2 (-m 13400)

```bash
hashcat -m 13400 -a 0 keepass.txt wordlist.txt
```

## KeePass 해시 추출

```bash
# keepass2john
keepass2john database.kdbx > keepass.hash
```

## 1Password (-m 6600, 6700, 8200)

```bash
# agilekeychain -m 6600
hashcat -m 6600 -a 0 1pass.txt wordlist.txt

# cloudkeychain -m 6700
hashcat -m 6700 -a 0 1pass_cloud.txt wordlist.txt
```

## LastPass (-m 6800)

```bash
hashcat -m 6800 -a 0 lastpass.txt wordlist.txt
```

## Apple Secure Notes (-m 16200)

```bash
hashcat -m 16200 -a 0 secure_notes.txt wordlist.txt
```

## 팁

- 패스워드 매니저 마스터 패스워드는 보통 길고 복잡. wordlist 품질 중요
- cewl로 타겟 관련 단어 수집 후 시도
- 시간 제한 두고 시도 (PBKDF2 반복으로 느림)