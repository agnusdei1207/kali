# xxd (GTFOBins)

## 개요

`xxd`는 hex dump를 만든다. GTFOBins에서 SUID로 실행될 때, 바이너리를 읽고 인젝션 가능한 문자열을 찾는 데 쓴다.

## 사용법

```bash
# 파일의 hex dump 출력
xxd /path/to/target

# 문자열 추출 (읽기 쉬운 형태)
strings /path/to/target | less
```

## 각 명령의 의미

| 명령 | 의미 |
|------|------|
| `xxd /path/to/target` | 대상 파일의 16진수 덤프 출력 |
| `strings /path/to/target \| less` | 사람이 읽을 수 있는 문자열만 추출 |

## GTFOBins 예시

```bash
# 파일 읽기 (파일이 존재하는지 확인)
LFILE=/root/root.txt
xxd "$LFILE" | xxd -r
```

- `/opt/xxd`가 존재하면 같은 방식을 쓸 수 있다.
- hex dump에서 명령어 인젝션 가능성은 보이지 않는다. 주로 바이너리 구조와 인자 해석을 본다.

## 주의

- 이 문서는 Linux 권한 상승의 하나 경로만 다룬다.
- Windows 권한 상승은 LOLBAS 문서 참고(04-privilege-escalation/windows 참고).
- 모든 시도는 합법적인 대상(본인 소유·허가받은 시스템)에서만 실행한다.

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
- 모든 시도는 합법적인 대상(본인 소유·허가받은 시스템)에서만 실행한다.
