# Hashcat 해시 식별

## hashid

```bash
hashid hash.txt
hashid -m hash.txt   # hashcat 모드 번호 포함
```

## hashcat 내장

```bash
# 예제 해시 목록
hashcat --example-hashes
hashcat --example-hashes | grep -i md5

# 도움말에서 모드 검색
hashcat --help | grep -i md5
hashcat -h | less
```

## haiti / name-that-hash

```bash
pip install name-that-hash
nth --text "5d41402abc4b2a76b9719d911017c592"
```

## 실전 워크플로

1. 해시 길이/문자셋으로 1차 추정
2. `hashid`로 후보 모드 확인
3. `hashcat --example-hashes`로 형식 비교
4. 작은 wordlist로 시험 크래킹

## 팁

- 같은 길이의 해시가 여러 모드에 매핑될 수 있음. 시험 크래킹으로 확정
- salt 포함 해시는 형식(구분자)으로 모드 구분