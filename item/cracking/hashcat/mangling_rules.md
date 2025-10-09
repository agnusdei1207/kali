# Hashcat 맹글링 규칙

## 맹글링 규칙이란?

맹글링 규칙은 기본 워드리스트를 변형하여 더 많은 후보를 생성하는 방법입니다.

### 기본 개념

```
원본: password
규칙 적용 후:
- Password (첫 글자 대문자)
- password123 (숫자 추가)
- p@ssword (문자 치환)
- drowssap (뒤집기)
```

## 기본 규칙 명령어

### 대소문자 변환

```bash
u    # 모든 글자 대문자로 변환
l    # 모든 글자 소문자로 변환
c    # 첫 글자만 대문자로 변환
C    # 첫 글자 소문자, 나머지 대문자
t    # 대소문자 토글 (Toggle)
TN   # N번째 문자 토글 (T0 = 첫 번째)
```

### 문자 추가

```bash
$X   # 끝에 문자 X 추가
^X   # 앞에 문자 X 추가
$1$2$3  # 끝에 123 추가
^a^b    # 앞에 ba 추가 (역순)
```

### 문자 삭제

```bash
]    # 마지막 문자 삭제
[    # 첫 번째 문자 삭제
DN   # N번째 문자 삭제 (D0 = 첫 번째)
'N   # N번째부터 끝까지 삭제
```

### 문자 치환

```bash
sXY  # 모든 X를 Y로 치환
s@4  # 모든 @를 4로 치환
sa@  # 모든 a를 @로 치환
se3  # 모든 e를 3로 치환
```

### 문자 삽입

```bash
iNX  # N번째 위치에 X 삽입
i0!  # 맨 앞에 ! 삽입
i4@  # 4번째 위치에 @ 삽입
```

### 기타 변환

```bash
r    # 문자열 뒤집기 (reverse)
d    # 중복 (duplicate)
f    # 반영 (reflect) - 원본 + 뒤집은 것
{    # 왼쪽으로 한 칸 회전
}    # 오른쪽으로 한 칸 회전
```

## 내장 규칙 파일

### best64.rule

```bash
# 가장 효과적인 64개 규칙
hashcat -a 0 hash.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

### OneRuleToRuleThemAll.rule

```bash
# 가장 포괄적인 규칙 파일
wget https://github.com/NotSoSecure/password_cracking_rules/raw/master/OneRuleToRuleThemAll.rule

hashcat -a 0 hash.txt wordlist.txt -r OneRuleToRuleThemAll.rule
```

### 기타 내장 규칙

```bash
ls /usr/share/hashcat/rules/
# - best64.rule
# - combinator.rule
# - generated.rule
# - generated2.rule
# - leetspeak.rule
# - oscommerce.rule
# - rockyou-30000.rule
# - toggles-leet.rule
# - unix-ninja-leetspeak.rule
```

## 사용자 정의 규칙 작성

### 간단한 규칙 파일

```bash
# custom.rule 파일 생성
cat > custom.rule << 'EOF'
# 기본 규칙
:
# 첫 글자 대문자
c
# 끝에 123 추가
$1$2$3
# 첫 글자 대문자 + 123
c $1$2$3
# leet speak
sa@ se3 si1 so0
EOF
```

### 복합 규칙 예시

```bash
# advanced_custom.rule
cat > advanced_custom.rule << 'EOF'
# 기본 + 연도
$2$0$2$3
$2$0$2$4
$2$0$2$5

# 첫 글자 대문자 + 특수문자 + 숫자
c $! $1
c $@ $2
c $# $3

# leet speak + 연도
sa@ se3 si1 so0 $2$0$2$3
sa@ se3 si1 so0 $2$0$2$4

# 대소문자 토글 + 숫자
t $0$1
t $1$2
t $2$3
EOF
```

### 조건부 규칙

```bash
# 길이 기반 규칙
cat > length_based.rule << 'EOF'
# 8글자 미만인 경우만 적용
<8 $1$2$3
<8 c $1$2$3

# 6글자 이상인 경우만 적용
>6 sa@ se3
>6 c sa@ se3
EOF
```

## 실제 적용 예시

### 일반적인 패스워드 패턴

```bash
# 회사명 + 연도 패턴
cat > company.rule << 'EOF'
c $2$0$2$3
c $2$0$2$4
c $2$0$2$5
c $! $2$0$2$3
c $@ $2$0$2$4
EOF

# 사용
echo "company" | hashcat --stdout -r company.rule
# Company2023
# Company2024
# Company2025
# Company!2023
# Company@2024
```

### 개인정보 기반 패턴

```bash
# 이름 + 생일 패턴
cat > personal.rule << 'EOF'
# 첫 글자 대문자 + 4자리 숫자
c $1$9$9$0
c $1$9$8$5
c $1$9$9$5

# 이름 + 특수문자 + 숫자
c $1$2$3
c $@ $1$2
c $! $9$9
EOF
```

### 키보드 패턴

```bash
# 키보드 근접 문자 치환
cat > keyboard.rule << 'EOF'
# 일반적인 오타 패턴
sq1 sw2 se3 sr4 st5
sa@ ss$ sd# sf%
sz! sx@ sc# sv$
EOF
```

## 규칙 테스트 및 최적화

### 규칙 효과 확인

```bash
# 규칙이 생성하는 후보 확인
echo "password" | hashcat --stdout -r custom.rule | head -20

# 여러 단어로 테스트
echo -e "password\nadmin\nuser" | hashcat --stdout -r custom.rule
```

### 규칙 성능 측정

```bash
# 생성되는 후보 수 확인
wc -l wordlist.txt
echo "password" | hashcat --stdout -r best64.rule | wc -l

# 예상 시간 계산
# 원본 워드 수 × 규칙 변환 수 = 총 후보 수
```

### 규칙 조합

```bash
# 여러 규칙 파일 동시 적용
hashcat -a 0 hash.txt wordlist.txt \
  -r /usr/share/hashcat/rules/best64.rule \
  -r custom.rule
```

## 고급 규칙 기법

### 메모리 최적화

```bash
# 규칙을 파일로 분할
split -l 1000 large.rule rule_part_

# 순차 적용
for rule in rule_part_*; do
  hashcat -a 0 hash.txt wordlist.txt -r "$rule"
done
```

### 타겟별 특화 규칙

```bash
# 한국어 특화
cat > korean.rule << 'EOF'
# 한글 초성 + 숫자
$1$2$3$4
$0$1$1$5
$8$8$0$0

# 한국 회사 패턴
$s$k $l$g $k$t
EOF
```

## 규칙 디버깅

### 문법 확인

```bash
# 규칙 문법 오류 확인
hashcat --stdout -r custom.rule <<< "test" 2>&1 | grep -i error
```

### 성능 프로파일링

```bash
# 규칙별 성능 비교
time echo "password" | hashcat --stdout -r rule1.rule > /dev/null
time echo "password" | hashcat --stdout -r rule2.rule > /dev/null
```
