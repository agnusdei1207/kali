# Hashcat으로 압축파일 비밀번호 크래킹

## 지원하는 압축 형식

### ZIP 파일

- **전통적 ZIP 암호화**: `-m 17200` (PKZIP)
- **AES 암호화 ZIP**: `-m 13600` (WinZip AES)

### RAR 파일

- **RAR3**: `-m 12500`
- **RAR5**: `-m 13000`

### 7-Zip 파일

- **7-Zip**: `-m 11600`

## ZIP 파일 크래킹

### 1. 해시 추출

#### zip2john 사용

```bash
# John the Ripper 도구로 해시 추출
zip2john archive.zip > zip.hash

# 해시 파일 확인
cat zip.hash
# archive.zip:$pkzip2$3*2*1*0*8*24*3e2c...
```

#### hashcat 형식으로 변환

```bash
# John 형식을 hashcat 형식으로 변환
sed 's/.*:\$pkzip2\$/\$pkzip2\$/' zip.hash > zip_hashcat.hash

# 또는 직접 추출 (Python)
python3 -c "
import zipfile
z = zipfile.ZipFile('archive.zip')
print('Hash extraction needed - use zip2john')
"
```

### 2. 크래킹 실행

#### 기본 사전 공격

```bash
# PKZIP 전통적 암호화
hashcat -m 17200 -a 0 zip.hash /usr/share/wordlists/rockyou.txt

# WinZip AES 암호화
hashcat -m 13600 -a 0 zip.hash /usr/share/wordlists/rockyou.txt
```

#### 규칙 적용

```bash
# 맹글링 규칙 적용
hashcat -m 17200 -a 0 zip.hash wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# 커스텀 규칙으로 연도 패턴
hashcat -m 17200 -a 0 zip.hash names.txt -r zip_custom.rule
```

#### 브루트포스 공격

```bash
# 4자리 숫자 (PIN)
hashcat -m 17200 -a 3 zip.hash ?d?d?d?d

# 6자리 영문 소문자
hashcat -m 17200 -a 3 zip.hash ?l?l?l?l?l?l

# 회사명 + 연도 패턴
hashcat -m 17200 -a 3 zip.hash company?d?d?d?d
```

## RAR 파일 크래킹

### 1. RAR 버전 확인

```bash
# RAR 파일 정보 확인
rar l archive.rar | head -10
unrar l archive.rar | head -10

# 또는 파일 시그니처 확인
hexdump -C archive.rar | head -1
```

### 2. 해시 추출

```bash
# rar2john 사용
rar2john archive.rar > rar.hash

# 해시 형식 확인
cat rar.hash
# RAR3: $RAR3$*0*...
# RAR5: $rar5$16$...
```

### 3. 크래킹 실행

```bash
# RAR3 크래킹
hashcat -m 12500 -a 0 rar.hash /usr/share/wordlists/rockyou.txt

# RAR5 크래킹 (더 강력한 암호화)
hashcat -m 13000 -a 0 rar.hash wordlist.txt -w 3

# 브루트포스 (RAR5는 매우 느림)
hashcat -m 13000 -a 3 rar.hash ?l?l?l?l?d?d
```

## 7-Zip 파일 크래킹

### 1. 해시 추출

```bash
# 7z2john 사용
7z2john archive.7z > 7z.hash

# 해시 확인
cat 7z.hash
# archive.7z:$7z$0$19$0$1$14$...
```

### 2. 크래킹 실행

```bash
# 7-Zip 크래킹
hashcat -m 11600 -a 0 7z.hash /usr/share/wordlists/rockyou.txt

# 성능 최적화
hashcat -m 11600 -a 0 7z.hash wordlist.txt -w 3 -O
```

## 실전 예시

### 시나리오 1: 기업 문서 ZIP

```bash
# 회사 관련 워드리스트 생성
cat > company_words.txt << 'EOF'
company
document
secret
confidential
project
2023
2024
2025
EOF

# 규칙 파일 생성
cat > company.rule << 'EOF'
# 첫 글자 대문자
c
# 대문자 + 연도
c $2$0$2$3
c $2$0$2$4
c $2$0$2$5
# 느낌표 추가
c $!
c $2$0$2$3 $!
EOF

# 크래킹 실행
hashcat -m 17200 -a 0 zip.hash company_words.txt -r company.rule
```

### 시나리오 2: 개인 백업 파일

```bash
# 개인정보 기반 워드리스트
cat > personal.txt << 'EOF'
password
admin
backup
family
photos
documents
important
EOF

# 생일/기념일 패턴 추가
hashcat -m 17200 -a 6 zip.hash personal.txt ?d?d?d?d
```

### 시나리오 3: CTF 문제

```bash
# CTF 관련 키워드
cat > ctf_words.txt << 'EOF'
flag
ctf
hack
cyber
security
challenge
EOF

# 단순한 변형 시도
hashcat -m 17200 -a 0 zip.hash ctf_words.txt -r /usr/share/hashcat/rules/best64.rule
```

## 성능 최적화

### GPU 활용

```bash
# 최대 성능 설정
hashcat -m 17200 -a 0 zip.hash wordlist.txt \
  -w 4 \
  -O \
  --status \
  --status-timer=30
```

### 메모리 관리

```bash
# 큰 워드리스트 분할
split -l 1000000 huge_wordlist.txt wordlist_part_

# 배치 처리
for part in wordlist_part_*; do
  hashcat -m 17200 -a 0 zip.hash "$part"
  if [ $? -eq 0 ]; then
    echo "Password found with $part"
    break
  fi
done
```

## 압축 형식별 특징

### ZIP 파일

- **속도**: 빠름
- **보안**: 상대적으로 약함 (전통적 암호화)
- **팁**: WinZip AES는 더 강력하지만 여전히 크래킹 가능

### RAR 파일

- **RAR3**: 중간 속도, 중간 보안
- **RAR5**: 매우 느림, 강력한 보안
- **팁**: RAR5는 시간 제한을 두고 크래킹

### 7-Zip 파일

- **속도**: 느림
- **보안**: 강함 (AES-256)
- **팁**: 강력한 GPU와 효율적인 워드리스트 필요

## 자동화 스크립트

### 압축파일 자동 크래킹

```bash
#!/bin/bash
# auto_crack.sh

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <archive_file>"
    exit 1
fi

ARCHIVE="$1"
EXT="${ARCHIVE##*.}"

case "$EXT" in
    "zip")
        echo "Cracking ZIP file..."
        zip2john "$ARCHIVE" > "${ARCHIVE}.hash"
        hashcat -m 17200 -a 0 "${ARCHIVE}.hash" /usr/share/wordlists/rockyou.txt
        ;;
    "rar")
        echo "Cracking RAR file..."
        rar2john "$ARCHIVE" > "${ARCHIVE}.hash"
        hashcat -m 12500 -a 0 "${ARCHIVE}.hash" /usr/share/wordlists/rockyou.txt
        ;;
    "7z")
        echo "Cracking 7-Zip file..."
        7z2john "$ARCHIVE" > "${ARCHIVE}.hash"
        hashcat -m 11600 -a 0 "${ARCHIVE}.hash" /usr/share/wordlists/rockyou.txt
        ;;
    *)
        echo "Unsupported format: $EXT"
        exit 1
        ;;
esac
```

## 주의사항

### 합법성

- 본인 소유 파일만 크래킹
- 침투 테스트 범위 내에서만 사용
- 적절한 권한 획득 후 진행

### 성능 고려

- **RAR5**: 매우 느려서 현실적 시간 내 불가능할 수 있음
- **7-Zip**: GPU 가속 필수
- **ZIP**: 상대적으로 빠르지만 워드리스트 품질이 중요

### 실용적 팁

1. **워드리스트 우선순위**: 파일 이름, 폴더명, 관련 키워드 먼저
2. **규칙 적용**: 연도, 특수문자 조합 시도
3. **시간 제한**: 24-48시간 내 결과 없으면 다른 방법 고려
4. **하이브리드 공격**: 워드리스트 + 숫자 조합이 효과적
