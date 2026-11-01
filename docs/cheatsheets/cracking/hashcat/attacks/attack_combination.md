# Hashcat 조합 공격 (Combination Attack, -a 1)

두 워드리스트의 단어를 이어 붙여 후보를 만든다. `wordlist1`의 각 단어 뒤에 `wordlist2`의 각 단어를 붙인다.

## 기본

```bash
hashcat -m 0 -a 1 hash.txt wordlist1.txt wordlist2.txt
```

## 활용 예시

이름 + 연도, 단어 + 숫자 조합에 유리하다.

```bash
# 이름 목록 + 연도 목록
printf 'john\nmary\n' > names.txt
printf '2023\n2024\n2025\n' > years.txt
hashcat -m 0 -a 1 hash.txt names.txt years.txt
```

## 주의

- 후보 수 = len(wordlist1) x len(wordlist2). 크면 메모리/시간 폭발
- 각 워드리스트는 작게 유지하고 규칙으로 확장하는 편이 효율적
- 조합 공격은 마스크나 하이브리드로 대체 가능한 경우가 많음