# Hashcat 기본 옵션

## 필수 옵션

### 해시 타입 (-m)

```bash
# 주요 해시 타입
-m 0     # MD5
-m 100   # SHA1
-m 1000  # NTLM
-m 1400  # SHA256
-m 1700  # SHA512
-m 1800  # sha512crypt
-m 500   # md5crypt
-m 22000 # WPA/WPA2
```

### 어택 모드 (-a)

```bash
-a 0  # 사전 공격 (Straight)
-a 1  # 조합 공격 (Combination)
-a 3  # 브루트포스 공격 (Brute-force)
-a 6  # 하이브리드 워드리스트 + 마스크
-a 7  # 하이브리드 마스크 + 워드리스트
```

## 성능 옵션

### 워크로드 (-w)

```bash
-w 1  # 낮음 (데스크톱 사용 가능)
-w 2  # 기본값
-w 3  # 높음 (전용 크래킹)
-w 4  # 악몽 (시스템 불안정 가능)
```

### 최적화 (-O)

```bash
-O     # 최적화된 커널 사용
       # 비밀번호 길이 제한 있음
       # 약 2배 빠름
```

### 디바이스 선택 (-d)

```bash
-d 1        # 첫 번째 GPU만 사용
-d 1,2      # 1번, 2번 GPU 사용
-d 1,2,3    # 여러 GPU 동시 사용
```

## 출력 옵션

### 상태 정보

```bash
--status           # 상태 자동 출력
--status-timer=60  # 60초마다 상태 출력
```

### 결과 저장

```bash
-o output.txt      # 크래킹된 결과 저장
--outfile-format=2 # 해시:평문 형식
```

### 진행률 표시

```bash
--show             # 이미 크래킹된 해시 표시
--left             # 남은 해시만 표시
```

## 세션 관리

### 세션 저장/복구

```bash
--session=mysession    # 세션 이름 지정
--restore             # 중단된 세션 복구
```

### 자동 체크포인트

```bash
--checkpoint-enable    # 체크포인트 활성화
--checkpoint-disable   # 체크포인트 비활성화
```

## 고급 옵션

### 메모리 관리

```bash
--bitmap-min=24       # 비트맵 최소 크기
--bitmap-max=24       # 비트맵 최대 크기
```

### 커널 튜닝

```bash
--kernel-accel=1024   # 커널 가속도
--kernel-loops=1024   # 커널 루프
```

### 온도 제어

```bash
--hwmon-temp-abort=90  # 90도에서 중단
```

## 디버깅 옵션

### 상세 정보

```bash
-v, --version         # 버전 정보
--help               # 도움말
--example-hashes     # 예제 해시들
```

### 벤치마크

```bash
-b                   # 벤치마크 실행
--benchmark-all      # 모든 해시 타입 벤치마크
```
