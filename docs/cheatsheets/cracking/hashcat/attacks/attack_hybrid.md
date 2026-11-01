# Hashcat 하이브리드 공격 (Hybrid, -a 6 / -a 7)

사전 단어와 마스크를 결합한다.

## -a 6: 워드리스트 + 마스크 (단어 뒤에 패턴)

```bash
# 단어 뒤에 3자리 숫자
hashcat -m 0 -a 6 hash.txt wordlist.txt ?d?d?d

# 단어 뒤에 연도
hashcat -m 0 -a 6 hash.txt wordlist.txt ?d?d?d?d
```

## -a 7: 마스크 + 워드리스트 (단어 앞에 패턴)

```bash
# 2자리 숫자 + 단어
hashcat -m 0 -a 7 hash.txt ?d?d wordlist.txt
```

## 활용 예시

```bash
# 비밀번호 뒤에 ! 추가
hashcat -m 0 -a 6 hash.txt wordlist.txt !

# birth year + name
hashcat -m 0 -a 7 hash.txt ?d?d?d?d names.txt
```

## 주의

- 하이브리드는 사전 공격 다음 단계로 효과적
- 마스크 부분의 키스페이스가 크면 시간 폭발
- 조합 공격(-a 1)과 달리 한쪽은 마스크 고정 패턴