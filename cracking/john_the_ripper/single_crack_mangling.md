# John the Ripper Single Crack Mode Mangling

## 개요

싱글 크랙 모드는 사용자명을 기반으로 패스워드를 추측하는 모드입니다. 맹글링 룰을 사용해 사용자명을 변형하여 일반적인 패스워드 패턴을 생성합니다.

## 기본 사용법

### 1. 기본 싱글 크랙 모드 실행

```bash
john --single hashfile
```

### 2. 특정 해시 타입 지정

```bash
john --single --format=NT hashfile
john --single --format=md5crypt hashfile
john --single --format=sha512crypt hashfile
```

### 3. 맹글링 룰 적용

```bash
# 기본 맹글링 룰 사용
john --single --rules hashfile

# 특정 룰셋 지정
john --single --rules=Single hashfile
john --single --rules=Wordlist hashfile
```

## 맹글링 패턴 예시

### 사용자명이 "admin"인 경우 생성되는 패스워드:

- admin
- admin123
- admin2023
- admin!
- Admin
- ADMIN
- nimda (역순)
- 4dm1n (leet speak)
- admin01
- admin2024

## 실제 사용 시나리오

### 1. Linux 패스워드 크랙

```bash
# /etc/passwd와 /etc/shadow 결합
unshadow /etc/passwd /etc/shadow > mypasswd

# 싱글 모드로 크랙
john --single mypasswd
```

### 2. Windows 해시 크랙

```bash
# SAM 덤프에서 추출한 NTLM 해시
john --single --format=NT ntlm_hashes.txt
```

### 3. 웹 애플리케이션 해시

```bash
# MD5 해시 크랙
john --single --format=raw-md5 md5_hashes.txt

# bcrypt 해시 크랙
john --single --format=bcrypt bcrypt_hashes.txt
```

## 맹글링 룰 커스터마이징

### john.conf 파일에서 Single 룰 수정

```bash
# 설정 파일 위치 확인
john --list=conf

# 커스텀 룰 예시 (john.conf에 추가)
[List.Rules:CustomSingle]
# 숫자 추가
$[0-9]$[0-9]
# 특수문자 추가
$!
$@
$#
# 대소문자 변경
c
u
l
```

### 커스텀 룰 사용

```bash
john --single --rules=CustomSingle hashfile
```

## 효율적인 크랙 전략

### 1. 단계별 접근

```bash
# 1단계: 맹글링 없이 기본 실행
john --single hashfile

# 2단계: 기본 맹글링 룰 적용
john --single --rules hashfile

# 3단계: 더 복잡한 룰 적용
john --single --rules=Jumbo hashfile
```

### 2. 시간 제한 설정

```bash
# 10분 동안만 실행
timeout 600 john --single --rules hashfile
```

### 3. 결과 확인

```bash
# 크랙된 패스워드 확인
john --show hashfile

# 현재 상태 확인
john --status
```

## 팁

- 사용자명 정보가 정확해야 효과적
- GECOS 필드 정보 활용 시 더 효과적
- 짧은 패스워드에 특히 효과적
- 다른 모드(wordlist, incremental)와 조합하여 사용

## 제한사항

- 사용자명과 관련 없는 패스워드는 찾지 못함
- 복잡한 패스워드에는 효과 제한적
- 사용자명 정보가 부족하면 비효율적
