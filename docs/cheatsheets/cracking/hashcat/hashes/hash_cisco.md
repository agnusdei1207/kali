# Hashcat Cisco 해시 (-m 500? no, Cisco IOS)

> 무엇: Cisco·네트워크 장비 해시 크래킹 모음 — Cisco PIX MD5(-m 2400), IOS type 5 MD5 crypt(-m 500), type 8 PBKDF2-SHA256(-m 9200), type 9 scrypt(-m 9300), ASA MD5(-m 2410), Fortigate(-m 7000)
> 언제: 네트워크 장비 설정 덤프에서 enable secret·username secret 라인을 확보해 장비 접속 패스워드를 알아낼 때
> 조건: hashcat 설치, 설정 파일에서 해시 추출 — type 9(scrypt)은 GPU 가속이 어려워 시간 제한을 두고 시도

## Cisco PIX MD5 (-m 2400)

```bash
hashcat -m 2400 -a 0 cisco_pix.txt wordlist.txt
```

## Cisco IOS $1$ (MD5) (-m 500? no). Cisco IOS type 5 = MD5 (-m 500? Actually Cisco IOS type 5 is MD5 crypt -m 500). Use -m 500.

```bash
hashcat -m 500 -a 0 cisco_ios5.txt wordlist.txt
```

## Cisco IOS $8$ (PBKDF2-SHA256) (-m 9200)

```bash
hashcat -m 9200 -a 0 cisco_ios8.txt wordlist.txt
```

## Cisco IOS $9$ (scrypt) (-m 9300)

```bash
hashcat -m 9300 -a 0 cisco_ios9.txt wordlist.txt
```

## Cisco ASA MD5 (-m 2410)

```bash
hashcat -m 2410 -a 0 cisco_asa.txt wordlist.txt
```

## Fortigate (-m 7000)

```bash
hashcat -m 7000 -a 0 fortigate.txt wordlist.txt
```

## 팁

- Cisco $9$ (scrypt)는 GPU 가속 어려움. 시간 제한 두고 시도
- 설정 파일에서 `enable secret` / `username ... secret` 추출