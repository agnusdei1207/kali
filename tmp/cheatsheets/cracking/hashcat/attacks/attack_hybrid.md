# Hashcat 하이브리드 공격 (Hybrid, -a 6 / -a 7)

- hashcat -a 6(워드리스트 뒤에 마스크 패턴)과 -a 7(마스크 패턴 뒤에 워드리스트) 하이브리드 공격 — 사전 단어 한쪽에 고정 마스크 패턴을 결합해 후보를 생성
- 사전 공격이 실패하고 패스워드가 단어+숫자·특수문자 결합(예: password123, 2024john, 단어 끝에 !)일 것으로 추정될 때 사전 공격 바로 다음 단계에서 시도
- hashcat 설치와 워드리스트, 패턴 위치(앞/뒤)와 마스크 문자셋에 대한 추정 — 마스크 부분 키스페이스가 크면 시간 폭발

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