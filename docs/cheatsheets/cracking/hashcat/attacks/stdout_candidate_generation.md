# Hashcat stdout 후보 생성 (--stdout)

크래킹 없이 규칙/마스크 적용 결과만 출력. 워드리스트 확장에 사용.

## 규칙 적용 결과 미리보기

```bash
echo "password" | hashcat --stdout -r /usr/share/hashcat/rules/best64.rule
cat wordlist.txt | hashcat --stdout -r custom.rule | head -20
```

## 마스크 후보 생성

```bash
hashcat --stdout -a 3 ?d?d?d?d > pins.txt
hashcat --stdout -a 3 ?l?l?l?l?l?l > six_lower.txt
```

## 조합 후보 생성

```bash
hashcat --stdout -a 1 list1.txt list2.txt > combined.txt
```

## 하이브리드 후보 생성

```bash
hashcat --stdout -a 6 wordlist.txt ?d?d?d > hybrid.txt
```

## 워드리스트 확장 파이프라인

```bash
cat base.txt \
  | hashcat --stdout -r /usr/share/hashcat/rules/best64.rule \
  | sort -u > expanded.txt
```

## 팁

- `--stdout`은 GPU 미사용. CPU에서 빠르게 생성
- 결과가 크면 디스크 공간 주의
- 중복 제거는 `sort -u`