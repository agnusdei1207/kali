# Hashcat 워드리스트 준비

## 정제

```bash
# 중복 제거
sort -u wordlist.txt > wordlist_unique.txt

# 길이 필터
awk 'length($0) >= 8 && length($0) <= 16' wordlist.txt > wordlist_8_16.txt

# 빈 줄 제거
grep -v '^$' wordlist.txt > wordlist_clean.txt

# 특정 문자셋만
grep -E '^[a-zA-Z0-9]+$' wordlist.txt > wordlist_alnum.txt
```

## 변환

```bash
# 대소문자
tr 'a-z' 'A-Z' < wordlist.txt > wordlist_upper.txt

# 인코딩 변환
iconv -f UTF-8 -t ASCII//TRANSLIT wordlist.txt > wordlist_ascii.txt
```

## 타겟 맞춤 (cewl)

```bash
cewl http://target.com -d 2 -m 5 -w target_words.txt
cewl http://target.com -d 2 -m 5 --with-numbers -w target_words.txt
```

## 조합 생성

```bash
# 두 리스트 조합 (cartesian)
# hashcat -a 1이 더 효율적. 셸에서는:
while read a; do while read b; do echo "$a$b"; done < list2.txt; done < list1.txt > combined.txt
```

## 인기 워드리스트

- /usr/share/wordlists/rockyou.txt
- /usr/share/seclists/Passwords/
- /usr/share/wordlists/fasttrack.txt

## 팁

- 규칙 적용 전 워드리스트 품질이 결정적
- 타겟 관련 단어(회사명, 인명, 날짜) 우선
- 너무 큰 워드리스트는 분할 처리