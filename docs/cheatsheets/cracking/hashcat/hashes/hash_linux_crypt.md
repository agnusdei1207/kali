# Hashcat Linux crypt 해시 (-m 500, 7400, 1800, 3200)

> 무엇: Linux /etc/shadow crypt 해시 크래킹 — md5crypt $1$(-m 500), sha256crypt $5$(-m 7400), sha512crypt $6$(-m 1800), bcrypt $2*$(-m 3200), unshadow 추출 포함
> 언제: /etc/shadow를 읽거나 unshadow로 통합 파일을 만든 뒤 로컬 계정 패스워드를 알아낼 때
> 조건: shadow 파일 읽기 권한(root) 또는 확보된 해시 파일, hashcat 설치 — sha512crypt·bcrypt는 salt 반복으로 매우 느림, md5crypt·sha256crypt부터 시도하고 cewl 타겟 워드리스트 고려

/etc/shadow 크래킹.

## md5crypt $1$ (-m 500)

```bash
hashcat -m 500 -a 0 shadow.txt wordlist.txt
```

## sha256crypt $5$ (-m 7400)

```bash
hashcat -m 7400 -a 0 shadow.txt wordlist.txt
```

## sha512crypt $6$ (-m 1800)

```bash
hashcat -m 1800 -a 0 shadow.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1800 -a 0 shadow.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

## bcrypt $2*$ (-m 3200)

```bash
hashcat -m 3200 -a 0 bcrypt.txt wordlist.txt
```

## 해시 추출

```bash
# /etc/shadow 직접
sudo cat /etc/shadow

# unshadow (John)
unshadow /etc/passwd /etc/shadow > unshadowed.txt

# hashcat 형식: $6$salt$hash 형태 한 줄
```

## 팁

- bcrypt/sha512crypt는 salt 반복으로 매우 느림
- 먼저 md5crypt, sha256crypt 시도 후 bcrypt/sha512crypt
- wordlist 품질이 결정적. cewl로 타겟 맞춤 단어 생성 고려