# RAR 파일과 John the Ripper 크래킹

## 1. RAR 파일이란?

- WinRAR에서 개발한 압축 파일 형식
- ZIP보다 압축률이 높고 오류 복구 기능 지원
- RAR3, RAR5 두 버전으로 나뉨 (RAR5가 더 보안이 강함)

---

## 2. rar2john 설치

### Ubuntu/Debian

```bash
sudo apt update
sudo apt install john
```

### 확인

```bash
which rar2john
rar2john --help
```

- `rar2john`은 `john` 패키지에 포함되어 있음

---

## 3. RAR 버전 확인하기

### 버전 확인 방법

```bash
# RAR 파일 정보 보기
rar l target.rar | head -10
unrar l target.rar | head -10

# 헥스 덤프로 시그니처 확인
hexdump -C target.rar | head -1
```

### 버전별 특징

- **RAR3**: 구버전, 크래킹이 상대적으로 빠름
- **RAR5**: 신버전, 강력한 암호화로 크래킹이 매우 느림

---

## 4. rar2john 사용법

### 기본 해시 추출

```bash
rar2john target.rar > rar_hash.txt
```

### 해시 확인

```bash
cat rar_hash.txt
```

- **RAR3 해시**: `$RAR3$*0*...`
- **RAR5 해시**: `$rar5$16$...`

---

## 5. John the Ripper로 크래킹

### 사전 공격

```bash
# rockyou.txt 사용
john --wordlist=/usr/share/wordlists/rockyou.txt rar_hash.txt

# 커스텀 워드리스트
john --wordlist=custom_wordlist.txt rar_hash.txt
```

### 규칙 적용

```bash
# 기본 규칙 적용
john --wordlist=/usr/share/wordlists/rockyou.txt --rules rar_hash.txt

# 커스텀 규칙
john --wordlist=wordlist.txt --rules=custom rar_hash.txt
```

### 브루트포스

```bash
# 4자리 숫자
john --mask=?d?d?d?d rar_hash.txt

# 소문자 + 숫자 조합
john --mask=?l?l?l?d?d rar_hash.txt
```

---

## 6. 실전 예시

### 기본 크래킹 과정

```bash
# 1단계: 해시 추출
rar2john confidential.rar > rar_hash.txt

# 2단계: 해시 타입 확인
cat rar_hash.txt

# 3단계: 사전 공격
john --wordlist=/usr/share/wordlists/rockyou.txt rar_hash.txt

# 4단계: 결과 확인
john --show rar_hash.txt
```

### 진행 상황 확인

```bash
# 실시간 진행 상황
john --status

# 현재 시도중인 패스워드 확인
john --status=rar_hash.txt
```

---

## 7. Hashcat과 병행 사용

### Hashcat 해시 변환

```bash
# John 해시를 Hashcat 형식으로 변환
john --format=rar --list=format-details
```

### Hashcat 직접 사용

```bash
# RAR3 크래킹
hashcat -m 12500 -a 0 rar_hash.txt /usr/share/wordlists/rockyou.txt

# RAR5 크래킹
hashcat -m 13000 -a 0 rar_hash.txt /usr/share/wordlists/rockyou.txt
```

---

## 8. 성능 최적화

### 멀티코어 활용

```bash
# 포크 개수 지정
john --fork=4 --wordlist=/usr/share/wordlists/rockyou.txt rar_hash.txt
```

### 세션 관리

```bash
# 세션 시작
john --session=rar_crack --wordlist=wordlist.txt rar_hash.txt

# 세션 복구
john --restore=rar_crack
```

---

## 9. 주의사항

### RAR5의 한계

- RAR5는 크래킹이 극도로 느림
- GPU 가속도 제한적
- 강력한 패스워드라면 거의 불가능

### 메모리 사용량

```bash
# 메모리 제한 설정
john --max-memory=4096 rar_hash.txt
```

---

## 10. 문제 해결

### 권한 오류

```bash
# RAR 파일 읽기 권한 확인
ls -la target.rar
chmod 644 target.rar
```

### 손상된 RAR 파일

```bash
# 파일 무결성 검사
rar t target.rar
unrar t target.rar
```

---

## 11. 고급 기법

### 하이브리드 공격

```bash
# 단어 + 숫자 조합
john --wordlist=wordlist.txt --mask='?w?d?d' rar_hash.txt
```

### 시간 기반 공격

```bash
# 특정 시간 후 중단
timeout 3600 john --wordlist=huge_wordlist.txt rar_hash.txt
```

---

## 참고 링크

- [John the Ripper 공식 문서](https://www.openwall.com/john/)
- [Hashcat RAR 크래킹](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [RAR 파일 형식 분석](https://www.rarlab.com/technote.htm)
