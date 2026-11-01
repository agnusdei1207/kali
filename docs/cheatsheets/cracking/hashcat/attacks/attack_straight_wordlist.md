# Hashcat 사전 공격 (Straight Attack, -a 0)

워드리스트의 단어를 그대로 후보로 쓰는 기본 공격. 가장 먼저 시도한다.

## 기본

```bash
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1000 -a 0 ntlm.txt /usr/share/wordlists/rockyou.txt
```

## 규칙과 결합

```bash
hashcat -m 0 -a 0 hash.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 0 -a 0 hash.txt wordlist.txt -r rule1.rule -r rule2.rule
```

## 결과 저장과 표시

```bash
hashcat -m 0 -a 0 hash.txt wordlist.txt -o cracked.txt
hashcat -m 0 hash.txt --show
hashcat -m 0 hash.txt --left
```

## 성능 옵션과 함께

```bash
hashcat -m 0 -a 0 hash.txt wordlist.txt -w 3 -O --status --status-timer=60
```

## 팁

- 워드리스트는 중복 제거 후 사용: `sort -u wordlist.txt > wordlist_unique.txt`
- 길이별 분류: `awk 'length($0) >= 8' wordlist.txt > wordlist_8plus.txt`
- potfile에 이미 크랙된 해시는 자동 스킵된다. `--potfile-disable`로 비활성화 가능
- 규칙은 `hashcat --stdout -r rule.txt < wordlist.txt | head` 로 먼저 미리보기