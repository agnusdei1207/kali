# Hashcat 고전 Unix / 레거시 해시

- 고전 Unix·레거시 해시 크래킹 모음 — LM(-m 3000), DES descrypt(-m 1500), BSDi crypt(-m 12400), AIX smd5/ssha256/ssha512(-m 6300/6400/6500), MD4(-m 900)
- 구형 시스템·레거시 인증 데이터베이스에서 해시를 덤프했을 때. LM은 7자 단위 분할 크래킹으로 빠르게 시도 가능
- hashcat 설치 — LM·descrypt(salt 2자)는 빠르지만 레거시 전용, AIX crypt은 느려 시간 제한 권장

## LM (-m 3000)

```bash
hashcat -m 3000 -a 3 lm.txt ?a?a?a?a?a?a?a?
```

## DES (descrypt) (-m 1500)

```bash
hashcat -m 1500 -a 0 descrypt.txt wordlist.txt
```

## BSDi Crypt (extended DES) (-m 12400)

```bash
hashcat -m 12400 -a 0 bsdicrypt.txt wordlist.txt
```

## AIX {smd5} (-m 6300)

```bash
hashcat -m 6300 -a 0 aix_smd5.txt wordlist.txt
```

## AIX {ssha256} (-m 6400)

```bash
hashcat -m 6400 -a 0 aix_ssha256.txt wordlist.txt
```

## AIX {ssha512} (-m 6500)

```bash
hashcat -m 6500 -a 0 aix_ssha512.txt wordlist.txt
```

## MD4 (-m 900)

```bash
hashcat -m 900 -a 0 md4.txt wordlist.txt
```

## Cisco PIX/ASA (-m 2400/2410) → hash_cisco.md 참고

## 팁

- LM은 7자 단위로 분할 크래킹. 레거시 시스템에서만
- descrypt는 salt 2자. 빠름
- AIX crypt은 느림. 시간 제한 두고 시도