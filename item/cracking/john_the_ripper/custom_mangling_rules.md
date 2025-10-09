# John the Ripper 커스텀 맹글링 룰 완전 가이드

## 중요! 시작하기 전에 알아야 할 것

### --single 모드의 필수 조건

**해시 파일 형식이 반드시 이 형태여야 함:**

```
사용자명:해시값
```

**예시:**

```
admin:$6$salt$hash...
john:5d41402abc4b2a76b9719d911017c592
mike:$1$salt$qmtDvdrdQfkF6P2V3fGe01
```

⚠️ **만약 해시만 있고 사용자명이 없다면 --single 모드는 효과가 없음!**

## 1. 기본 맹글링 룰 이해하기

### John 설정 파일 위치 확인

```bash
john --list=conf
# 보통 /etc/john/john.conf 또는 ~/.john/john.conf
```

### 현재 사용 가능한 룰 확인

```bash
john --list=rules
```

### 기본 Single 룰 동작 방식

사용자명이 `mike`인 경우:

- mike
- Mike
- MIKE
- mike123
- mike1
- mike2023
- mike!
- mike@
- mike#
- ekim (역순)
- m1ke (leet speak)

## 2. 실습용 해시 파일 만들기

### 테스트용 해시 생성

```bash
# MD5 해시 생성 (테스트용)
echo -n "mike123" | md5sum
# 결과: 5d41402abc4b2a76b9719d911017c592

# 해시 파일 생성
echo "mike:5d41402abc4b2a76b9719d911017c592" > test_hashes.txt
echo "admin:21232f297a57a5a743894a0e4a801fc3" >> test_hashes.txt
echo "john:527bd5b5d689e2c32ae974c6229ff785" >> test_hashes.txt
```

## 3. 커스텀 맹글링 룰 만들기

### 기본 룰 문법

| 문법    | 설명             | 예시           |
| ------- | ---------------- | -------------- |
| `$문자` | 끝에 문자 추가   | `$1` → mike1   |
| `^문자` | 앞에 문자 추가   | `^1` → 1mike   |
| `c`     | 첫 글자만 대문자 | `c` → Mike     |
| `u`     | 모든 글자 대문자 | `u` → MIKE     |
| `l`     | 모든 글자 소문자 | `l` → mike     |
| `r`     | 문자열 뒤집기    | `r` → ekim     |
| `d`     | 단어 복제        | `d` → mikemike |
| `f`     | 단어 반사        | `f` → mikeekim |

### 커스텀 룰 파일 생성

```bash
# 커스텀 룰 파일 생성
cat > custom_rules.conf << 'EOF'
[List.Rules:MyCustom]
# 숫자 1자리 추가
$0
$1
$2
$3
$4
$5
$6
$7
$8
$9

# 숫자 2자리 추가
$1$0
$1$1
$1$2
$1$3
$2$0
$2$1
$2$2
$2$3

# 특수문자 추가
$!
$@
$#
$$
$%

# 대소문자 변형
c
u
l

# 연도 추가
$2$0$2$3
$2$0$2$4
$2$0$2$5

# 조합 룰 (첫글자 대문자 + 숫자)
c$1
c$2
c$3
c$1$2
c$1$3
c$2$3

# 조합 룰 (첫글자 대문자 + 특수문자)
c$!
c$@
c$#

# 복잡한 조합
c$1$2$3
c$2$0$2$3
c$2$0$2$4
EOF
```

## 4. 현업에서 자주 쓰이는 명령어 조합

### 단계별 크랙 전략

#### 1단계: 기본 Single 모드

```bash
john --single --format=raw-md5 test_hashes.txt
```

#### 2단계: 기본 맹글링 룰 적용

```bash
john --single --rules=Single --format=raw-md5 test_hashes.txt
```

#### 3단계: 커스텀 룰 적용

```bash
john --single --rules=MyCustom --format=raw-md5 --rules-file=custom_rules.conf test_hashes.txt
```

#### 4단계: 시간 제한과 함께 실행

```bash
timeout 300 john --single --rules=MyCustom --format=raw-md5 test_hashes.txt
```

### 자주 사용하는 해시 형식별 명령어

#### NTLM 해시 (Windows)

```bash
john --single --rules=Single --format=NT ntlm_hashes.txt
```

#### SHA-256 해시

```bash
john --single --rules=Single --format=raw-sha256 sha256_hashes.txt
```

#### bcrypt 해시 (웹 애플리케이션)

```bash
john --single --rules=Single --format=bcrypt bcrypt_hashes.txt
```

#### Linux crypt 해시

```bash
john --single --rules=Single --format=sha512crypt shadow_hashes.txt
```

## 5. 고급 커스텀 룰 예시

### 회사명 기반 룰

```bash
cat > company_rules.conf << 'EOF'
[List.Rules:CompanyRules]
# 회사명이 사용자명에 포함될 경우
$C$o$m$p$a$n$y
$c$o$m$p$a$n$y
^C^o^m^p^a^n^y
^c^o^m^p^a^n^y

# 연도 + 회사명
$2$0$2$4$C$o$m$p
$C$o$m$p$2$0$2$4

# 부서명
$I$T
$H$R
$S$a$l$e$s
EOF
```

### 지역 기반 룰 (한국)

```bash
cat > korea_rules.conf << 'EOF'
[List.Rules:KoreaRules]
# 한국 지역 코드
$K$R
$k$r
$8$2

# 한국 연도 표기
$2$4  # 24년
$2$5  # 25년

# 한국식 비밀번호 패턴
$!$@
$1$2$3$4
$q$w$e$r
EOF
```

## 6. 실전 시나리오

### 시나리오 1: 회사 내부 계정 크랙

```bash
# 1. 사용자 목록으로 해시 파일 생성
cat employees.txt | while read user; do
    echo "$user:$(grep $user dumped_hashes.txt | cut -d: -f2)"
done > company_hashes.txt

# 2. 회사 정보 기반 커스텀 룰로 크랙
john --single --rules=CompanyRules --format=NT company_hashes.txt
```

### 시나리오 2: 웹 애플리케이션 사용자 크랙

```bash
# 1. 데이터베이스에서 추출한 사용자:해시 형태
cat > webapp_users.txt << 'EOF'
admin:$2b$10$salt$hash...
user123:$2b$10$salt$hash...
testuser:$2b$10$salt$hash...
EOF

# 2. bcrypt 형식으로 크랙
john --single --rules=Single --format=bcrypt webapp_users.txt
```

### 시나리오 3: Linux 서버 계정 크랙

```bash
# 1. unshadow로 파일 결합
unshadow /etc/passwd /etc/shadow > linux_accounts.txt

# 2. SHA-512 형식으로 크랙
john --single --rules=Single --format=sha512crypt linux_accounts.txt
```

## 7. 성능 최적화 팁

### 병렬 처리

```bash
# CPU 코어 수만큼 병렬 실행
john --single --rules=Single --format=NT --fork=4 hashes.txt
```

### 메모리 사용량 제한

```bash
# 메모리 사용량 제한 (예: 1GB)
john --single --rules=Single --format=NT --max-mem=1024 hashes.txt
```

### 세션 관리

```bash
# 세션 이름 지정
john --single --rules=Single --session=mysession hashes.txt

# 세션 복구
john --restore=mysession
```

## 8. 결과 분석 및 확인

### 크랙된 패스워드 확인

```bash
john --show hashes.txt
john --show --format=NT ntlm_hashes.txt
```

### 통계 정보 확인

```bash
john --show --format=NT hashes.txt | grep -c ":"
```

### 크랙 속도 확인

```bash
john --test --format=NT
```

## 9. 문제 해결

### 해시 형식 확인

```bash
john --list=formats | grep -i md5
john --list=formats | grep -i sha
```

### 룰 문법 테스트

```bash
john --test-rules=Single
john --test-rules=MyCustom --rules-file=custom_rules.conf
```

### 디버그 모드

```bash
john --single --rules=Single --format=NT --verbosity=5 hashes.txt
```

## 10. 보안 주의사항

⚠️ **중요**: 이 도구는 오직 합법적인 보안 테스트 목적으로만 사용해야 합니다.

- 자신이 소유한 시스템에서만 사용
- 명시적 허가가 있는 시스템에서만 사용
- 불법적인 접근 시도에 사용 금지

## 마무리

커스텀 맹글링 룰은 특정 조직이나 환경에 맞춤화된 패스워드 크랙에 매우 효과적입니다. 사용자명 정보가 충분하고 정확할수록 더 높은 성공률을 보입니다.
