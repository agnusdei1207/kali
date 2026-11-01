# Hashcat 벤치마크와 성능 튜닝

## 벤치마크

```bash
# 전체 벤치마크
hashcat -b

# 특정 모드만
hashcat -b -m 0
hashcat -b -m 1000
hashcat -b -m 22000

# 모든 모드 벤치마크
hashcat -b --benchmark-all
```

## 워크로드 (-w)

```bash
-w 1  # 낮음 (데스크톱 사용 가능)
-w 2  # 기본값
-w 3  # 높음 (전용 크래킹)
-w 4  # 악몽 (시스템 불안정 가능)
```

## 최적화 (-O)

```bash
# 최적화 커널. 약 2배 빠름. 비밀번호 길이 제한 있음
hashcat -m 0 -a 0 hash.txt wordlist.txt -O
```

## 디바이스 선택 (-d)

```bash
-d 1        # 첫 번째 GPU만
-d 1,2      # 1,2번 GPU
-d 1,2,3,4  # 4개 GPU
```

## 커널 튜닝

```bash
--kernel-accel=1024
--kernel-loops=1024
--tune
```

## 성능 모니터링

```bash
# 상태 자동 출력
hashcat -m 0 hash.txt wordlist.txt --status --status-timer=60

# GPU 온도 중단
hashcat -m 0 hash.txt wordlist.txt --hwmon-temp-abort=85

# 디버그
hashcat --debug-mode=1 -m 0 hash.txt wordlist.txt
```

## 팁

- `-O`는 짧은 비밀번호에 유리. 길면 효과 감소
- VRAM 부족 시 해시 파일 분할: `split -l 1000 large_hash.txt part_`
- 다중 GPU는 `-d`로 지정. 자동 분산 아님