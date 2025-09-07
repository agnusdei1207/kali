## 기본 문법

```bash
hashcat -a <공격모드> -m <해시타입> <해시파일> <단어목록>

hashcat -m 3200 -a 0 ~/Hashing-Basics/Task-6/hash1.txt rockyou.txt
# 3200 bcrypt
# -a attack mode
# 0 Straight attack
# 1400 SHA-256

```

## 공격 모드 (-a)

- 0: 사전 공격 (Wordlist)
- 1: 조합 공격 (Combination)
- 3: 무차별 대입 공격 (Brute-force)
- 6: 규칙 기반 공격 (Rule-based)
- 7: Hybrid Wordlist + Mask
- 9: Hybrid Mask + Wordlist

## 주요 해시 타입 (-m) [필수]

- 0: MD5
- 100: SHA1
- 1000: NTLM
- 1800: sha512crypt (Linux)
- 3000: LM
- 5500: NetNTLMv1
- 5600: NetNTLMv2
- 13100: Kerberos 5 TGS-REP
- 2500: WPA/WPA2
- 16500: JWT (JSON Web Token)

## 자주 사용되는 옵션

- `-w <N>`: 워크로드 레벨(1-4)
- `-o <파일>`: 결과 출력 파일
- `--show`: 크랙된 해시 표시
- `--force`: 경고 무시하고 강제 실행
- `-r <파일>`: 규칙 파일 적용
- `--session <이름>`: 세션 이름 지정 (나중에 복구 가능)
- `--restore`: 중단된 세션 복구
- `--status`: 상태 모니터링 활성화
- `--potfile-disable`: potfile 사용 안 함
- `-O`: 최적화 모드 (더 빠르지만 메모리 더 사용)

## 사용 예시

### 1. MD5 해시 크래킹 (사전 공격)

```bash
hashcat -a 0 -m 0 hash.txt /usr/share/wordlists/rockyou.txt
```

### 2. NTLM 해시 크래킹

```bash
hashcat -a 0 -m 1000 ntlm.hash /usr/share/wordlists/rockyou.txt
```

### 3. 규칙 적용한 크래킹

```bash
hashcat -a 0 -m 1000 ntlm.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### 4. 무차별 대입 공격 (특정 패턴)

```bash
# 8자리 숫자만 시도
hashcat -a 3 -m 0 hash.txt ?d?d?d?d?d?d?d?d
```

### 5. NetNTLMv2 해시 크래킹

```bash
hashcat -a 0 -m 5600 netntlmv2.hash /usr/share/wordlists/rockyou.txt
```

### 6. 마스크 표기법

- ?l: 소문자 (a-z)
- ?u: 대문자 (A-Z)
- ?d: 숫자 (0-9)
- ?s: 특수문자 (!"#$% 등)
- ?a: 모든 문자

### 7. 조합 공격 예시 (두 단어목록 조합)

```bash
hashcat -a 1 -m 0 hash.txt wordlist1.txt wordlist2.txt
```

### 8. 마스크 + 단어목록 혼합 공격

```bash
# 단어 뒤에 2자리 숫자 추가
hashcat -a 7 -m 0 hash.txt wordlist.txt ?d?d
```

### 9. 세션 관리

```bash
# 세션 이름 지정해서 실행
hashcat -a 0 -m 0 hash.txt wordlist.txt --session cracking_session

# 중단된 세션 복구
hashcat --session cracking_session --restore
```

## 해시 식별 팁

먼저 hashid로 해시 유형 식별 후 해당 모드(-m) 선택:

```bash
hashid hash.txt
```

```bash
hashcat --help | grep -i hash-modes
hashcat --example-hashes
```
