# Hashcat 모바일 해시

Android, iOS, Apple 계정.

## Android FDE <= 4.3 (-m 8800)

```bash
hashcat -m 8800 -a 0 android.txt wordlist.txt
```

## Android 8+ (PBKDF2) -m 18400? no, 18400 is ODF. Android PIN -m 18400? Actually Android 8+ PIN is -m 18400? Let me use known: Android FDE (Samsung) etc. Skip uncertain.

## Android PIN (8-digit) 브루트포스

```bash
hashcat -m 8800 -a 3 android.txt ?d?d?d?d
```

## iOS (iTunes backup) (-m 14700, 14800)

```bash
# iTunes backup < 10.0 -m 14700
hashcat -m 14700 -a 0 itunes.txt wordlist.txt

# iTunes backup >= 10.0 -m 14800
hashcat -m 14800 -a 0 itunes10.txt wordlist.txt
```

## Apple Secure Notes (-m 16200)

```bash
hashcat -m 16200 -a 0 secure_notes.txt wordlist.txt
```

## Apple iWork (-m 18400? no). Skip.

## 팁

- 모바일 PIN은 짧음. 브루트포스 현실적
- iTunes backup 해시는 manifest.plist에서 추출