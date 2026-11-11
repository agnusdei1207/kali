# Hashcat stdout 후보 생성 (--stdout)

- hashcat --stdout — 실제 크래킹 없이 규칙(-r), 마스크(-a 3), 조합(-a 1), 하이브리드(-a 6) 적용 결과인 후보 패스워드를 텍스트로만 출력하는 모드
- 크래킹 전에 규칙·마스크가 어떤 후보를 만드는지 미리보기로 검증할 때, 또는 출력을 sort -u로 중복 제거해 확장 워드리스트 파일로 만들 때
- hashcat 설치(CPU만 사용, GPU 불필요), 입력 워드리스트·규칙 파일 — 생성량이 크면 디스크 공간 주의

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