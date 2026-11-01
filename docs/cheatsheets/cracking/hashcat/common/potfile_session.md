# Hashcat potfile, 세션, 복구

## potfile

크랙 결과가 `~/.hashcat/hashcat.potfile`에 저장되어 재실행 시 자동 스킵.

```bash
# potfile 비활성화
hashcat -m 0 hash.txt wordlist.txt --potfile-disable

# potfile 위치 지정
hashcat -m 0 hash.txt wordlist.txt --potfile-path=/tmp/my.pot

# potfile 내용 확인
cat ~/.hashcat/hashcat.potfile
```

## 세션 관리

```bash
# 세션 이름 지정
hashcat -m 0 -a 0 hash.txt wordlist.txt --session=crack1

# 중단된 세션 복구
hashcat --session=crack1 --restore

# 세션 파일 위치
ls ~/.hashcat/sessions/
```

## 체크포인트

```bash
# 체크포인트 활성화
hashcat -m 0 hash.txt wordlist.txt --checkpoint-enable --checkpoint-interval=300

# 수동 체크포인트 저장 (Ctrl+C)
# 복구 시 --restore 사용
```

## 결과 출력

```bash
# 결과 파일 저장
hashcat -m 0 hash.txt wordlist.txt -o cracked.txt

# 출력 형식 지정
hashcat -m 0 hash.txt --show --outfile-format=2
# 1: hash:plain
# 2: plain:hash
# 3: hash
# 4: plain

# 크래킹된 해시 표시
hashcat -m 0 hash.txt --show

# 남은 해시 표시
hashcat -m 0 hash.txt --left
```

## 팁

- 장시간 크래킹은 반드시 세션 이름 지정
- potfile은 다른 머신으로 이동 시 재사용 가능
- `--restore`는 같은 명령 옵션으로 재실행해야 함