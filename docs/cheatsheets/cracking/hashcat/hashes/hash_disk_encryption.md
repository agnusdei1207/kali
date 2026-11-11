# Hashcat 디스크 암호화 해시

> 무엇: 디스크·볼륨 암호화 크래킹 모음 — LUKS(-m 14600, luks2john), VeraCrypt(-m 13700 계열), TrueCrypt(-m 6211 계열), BitLocker(-m 22100, bitlocker2john), FileVault 2(-m 18300/16700)
> 언제: 디스크 이미지·VHD·암호화 파티션을 확보하고 복호화 패스워드가 필요할 때
> 조건: hashcat 설치와 GPU 가속 필수, 2john 계열 해시 추출 도구 — PBKDF2 반복으로 매우 느려 브루트포스보다 wordlist+규칙이 현실적

LUKS, VeraCrypt, TrueCrypt, BitLocker, FileVault.

## LUKS (-m 14600)

```bash
hashcat -m 14600 -a 0 luks.txt wordlist.txt
```

## LUKS 해시 추출

```bash
# luks2john
luks2john /dev/sda2 > luks.hash
```

## VeraCrypt (-m 13700 계열)

```bash
# VeraCrypt PBKDF2-HMAC-RIPEMD160 + XTS 512 (boot) -m 13711
hashcat -m 13711 -a 0 veracrypt.txt wordlist.txt

# 기본 -m 13700
hashcat -m 13700 -a 0 veracrypt.txt wordlist.txt
```

## TrueCrypt (-m 6211 계열)

```bash
# TrueCrypt 5.0+ PBKDF2-HMAC-RIPEMD160 + XTS 512 -m 6211
hashcat -m 6211 -a 0 truecrypt.txt wordlist.txt
```

## BitLocker (-m 22100)

```bash
hashcat -m 22100 -a 0 bitlocker.txt wordlist.txt
```

## BitLocker 해시 추출

```bash
# bitlocker2john
bitlocker2john -i image.vhd > bitlocker.hash
```

## FileVault 2 (-m 18300, 16700)

```bash
# Apple FileVault 2 -m 18300
hashcat -m 18300 -a 0 filevault.txt wordlist.txt

# FileVault 2 (PBKDF2) -m 16700
hashcat -m 16700 -a 0 filevault2.txt wordlist.txt
```

## 팁

- 디스크 암호화는 PBKDF2 반복으로 매우 느림
- GPU 가속 필수, 시간 제한 두고 시도
- 브루트포스보다 wordlist + 규칙이 현실적