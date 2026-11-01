# Hashcat 다중 해시 / 배치 처리

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