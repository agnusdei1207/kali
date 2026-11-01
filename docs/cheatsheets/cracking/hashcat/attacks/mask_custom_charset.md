# Hashcat 마스크 커스텀 문자셋

기본 문자셋으로 표현하기 어려운 패턴을 `-1`~`-4`로 정의한다.

## 정의와 사용

```bash
# -1 소문자+숫자
hashcat -m 0 -a 3 hash.txt -1 ?l?d ?1?1?1?1?1?1

# -2 대문자+특수문자
hashcat -m 0 -a 3 hash.txt -2 ?u?s ?2?2?2?2

# 직접 문자 지정
hashcat -m 0 -a 3 hash.txt -1 abcdef0123456789 ?1?1?1?1?1?1
```

## 실전 패턴

```bash
# PIN: 0-9만 6자리
hashcat -m 0 -a 3 hash.txt -1 0123456789 ?1?1?1?1?1?1

# 회사명 패턴: Company + 연도
hashcat -m 0 -a 3 hash.txt Company?d?d?d?d

# 키보드 워크 (qwerty 라인)
hashcat -m 0 -a 3 hash.txt -1 qwertyuiop ?1?1?1?1?1?1
```

## 팁

- 커스텀 문자셋은 마스크 내에서 `?1`~`?4`로 참조
- 한 마스크에서 여러 커스텀 문자셋을 섞어 사용 가능
- 키보드 워크·연도·이름 등 사전 정보를 문자셋으로 좁히면 효율적