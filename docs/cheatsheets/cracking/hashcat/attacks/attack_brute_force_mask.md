# Hashcat 브루트포스 / 마스크 공격 (Brute-force, -a 3)

- hashcat -a 3 마스크 공격 — ?l/?u/?d/?s 같은 문자셋 플레이스홀더로 패턴을 정의해 해당 키스페이스의 모든 조합을 전수 시도하는 브루트포스 방식
- 사전 공격과 규칙 기반 공격이 실패한 뒤, 패스워드 길이·구성(예: 4자리 PIN, 단어+숫자4)에 대한 단서가 있을 때 남은 후보를 전부 시도할 때
- hashcat 설치와 GPU 가속 환경(길이·문자셋별 소요 시간은 --benchmark로 사전 확인), 패스워드 패턴 정보 — 키스페이스가 크면 현실적 시간 내 완료 불가

마스크 패턴으로 가능한 모든 조합을 전수 조사한다.

## 기본 마스크

```bash
# 4자리 숫자
hashcat -m 0 -a 3 hash.txt ?d?d?d?d

# 8자리 소문자
hashcat -m 0 -a 3 hash.txt ?l?l?l?l?l?l?l?l

# 혼합 패턴 (대문자 + 소문자3 + 숫자4)
hashcat -m 0 -a 3 hash.txt ?u?l?l?l?d?d?d?d
```

## 기본 문자셋

```text
?l = 소문자 a-z
?u = 대문자 A-Z
?d = 숫자 0-9
?h = 16진수 소문자 0-9a-f
?H = 16진수 대문자 0-9A-F
?s = 특수문자
?a = 모든 문자 (?l?u?d?s)
?b = 0x00-0xff
```

## 커스텀 문자셋 (-1 ~ -4)

```bash
# -1 소문자+숫자, -2 대문자+특수문자
hashcat -m 0 -a 3 hash.txt -1 ?l?d -2 ?u?s ?1?1?1?1?1?1

# 직접 문자 지정
hashcat -m 0 -a 3 hash.txt -1 abc123 ?1?1?1?1
```

## 증분 모드 (길이 자동 증가)

```bash
hashcat -m 0 -a 3 hash.txt ?d?d?d?d --increment
hashcat -m 0 -a 3 hash.txt ?d?d?d?d --increment-min=4 --increment-max=8
```

## 고정 문자 포함

```bash
# admin + 4자리 숫자
hashcat -m 0 -a 3 hash.txt admin?d?d?d?d
```

## 팁

- 키스페이스가 크면 현실적 시간 내 불가. 가능한 패턴 정보를 활용
- `--increment`로 짧은 길이부터 시도
- `-O` 최적화로 속도 향상 (비밀번호 길이 제한 주의)