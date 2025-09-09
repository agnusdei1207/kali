# Hashcat 사용법

## 기본 사용법

### 단일 해시 크래킹

```bash
# MD5 해시 크래킹
hashcat -m 0 -a 0 hash.txt wordlist.txt

# SHA256 해시 크래킹
hashcat -m 1400 -a 0 hash.txt wordlist.txt
```

### 해시 파일 형식

```bash
# hash.txt 파일 예시
5d41402abc4b2a76b9719d911017c592
098f6bcd4621d373cade4e832627b4f6
```

## 어택 모드별 사용법

### 1. 사전 공격 (Straight Attack)

```bash
# 기본 사전 공격
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

# 규칙 적용
hashcat -m 0 -a 0 hash.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

### 2. 조합 공격 (Combination Attack)

```bash
# 두 워드리스트 조합
hashcat -m 0 -a 1 hash.txt wordlist1.txt wordlist2.txt
```

### 3. 브루트포스 공격 (Brute-force Attack)

```bash
# 4자리 숫자 브루트포스
hashcat -m 0 -a 3 hash.txt ?d?d?d?d

# 8자리 영문 소문자
hashcat -m 0 -a 3 hash.txt ?l?l?l?l?l?l?l?l

# 혼합 패턴
hashcat -m 0 -a 3 hash.txt ?u?l?l?l?d?d?d?d
```

### 4. 하이브리드 공격

```bash
# 워드리스트 + 숫자 3자리
hashcat -m 0 -a 6 hash.txt wordlist.txt ?d?d?d

# 숫자 2자리 + 워드리스트
hashcat -m 0 -a 7 hash.txt ?d?d wordlist.txt
```

## 마스크 패턴

### 기본 문자셋

```bash
?l = 소문자 (a-z)
?u = 대문자 (A-Z)
?d = 숫자 (0-9)
?h = 16진수 (0-9a-f)
?H = 16진수 대문자 (0-9A-F)
?s = 특수문자 (!@#$%^&*)
?a = 모든 문자 (?l?u?d?s)
?b = 0x00-0xff
```

### 사용자 정의 문자셋

```bash
# 커스텀 문자셋 정의
-1 ?l?d     # 소문자와 숫자
-2 ?u?s     # 대문자와 특수문자

# 사용
hashcat -m 0 -a 3 hash.txt -1 ?l?d ?1?1?1?1?1?1
```

## 실제 사용 예시

### Windows NTLM 해시

```bash
# NTLM 해시 크래킹
hashcat -m 1000 -a 0 ntlm.txt /usr/share/wordlists/rockyou.txt

# 규칙 적용
hashcat -m 1000 -a 0 ntlm.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

### Linux 해시 (sha512crypt)

```bash
# /etc/shadow 해시
hashcat -m 1800 -a 0 shadow.txt wordlist.txt
```

### WiFi WPA/WPA2

```bash
# WPA2 핸드셰이크 크래킹
hashcat -m 22000 -a 0 capture.hc22000 wordlist.txt
```

### ZIP 파일 암호

```bash
# ZIP 파일 해시 추출 후
zip2john archive.zip > zip.hash

# 해시 크래킹
hashcat -m 13600 -a 0 zip.hash wordlist.txt
```

## 성능 최적화 예시

### 고성능 설정

```bash
hashcat -m 0 -a 0 hash.txt wordlist.txt \
  -w 3 \
  -O \
  --status \
  --status-timer=60 \
  -o cracked.txt
```

### 다중 GPU 사용

```bash
hashcat -m 0 -a 0 hash.txt wordlist.txt \
  -d 1,2,3 \
  -w 4 \
  -O
```

## 세션 관리 예시

### 장시간 크래킹

```bash
# 세션 시작
hashcat -m 0 -a 0 hash.txt wordlist.txt \
  --session=long_crack \
  --checkpoint-enable

# 세션 복구
hashcat --restore --session=long_crack
```

## 결과 분석

### 크래킹된 결과 확인

```bash
# 결과 표시
hashcat -m 0 hash.txt --show

# 특정 형식으로 출력
hashcat -m 0 hash.txt --show --outfile-format=2
```

### 남은 해시 확인

```bash
# 크래킹되지 않은 해시
hashcat -m 0 hash.txt --left
```
