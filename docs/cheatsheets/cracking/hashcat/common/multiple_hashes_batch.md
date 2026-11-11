# Hashcat 다중 해시 / 배치 처리

- hashcat 다중 해시·배치 처리 — 해시를 한 줄에 하나씩 나열해 한 번에 병렬 크래킹하고, VRAM 부족 시 split으로 해시·워드리스트를 나눠 반복 처리하는 방법
- NTLM 덤프처럼 해시가 수백 개 이상일 때, 해시 파일이 커서 VRAM에 한 번에 안 올라갈 때
- hashcat 설치, 한 파일에는 동일 -m 모드의 해시만 — 분할 처리 시 potfile 공유로 중복 크래킹 방지, 각 배치는 --session으로 추적

## 다중 해시 파일

한 줄에 해시 하나. hashcat이 자동으로 병렬 처리.

```bash
# hash.txt
5d41402abc4b2a76b9719d911017c592
098f6bcd4621d373cade4e832627b4f6
```

```bash
hashcat -m 0 -a 0 hash.txt wordlist.txt
```

## 해시 분할 (VRAM 부족 시)

```bash
split -l 1000 large_hash.txt hash_part_
for f in hash_part_*; do
  hashcat -m 0 -a 0 "$f" wordlist.txt
done
```

## 워드리스트 분할

```bash
split -l 10000000 large_wordlist.txt wordlist_part_
for f in wordlist_part_*; do
  hashcat -m 0 -a 0 hash.txt "$f"
done
```

## 결과 확인

```bash
hashcat -m 0 hash.txt --show
hashcat -m 0 hash.txt --left
```

## 팁

- potfile로 이미 크랙된 해시 자동 스킵
- 분할 처리 시 potfile 공유로 중복 방지
- `--session`으로 각 배치 추적