# xxd (GTFOBins)

- SUID·sudo로 실행되는 xxd로 `xxd "$LFILE" | xxd -r`를 해 권한 밖 파일(/root/root.txt 등)을 읽어내는 GTFOBins 기법 문서
- flag가 root 홈에 있어 일반 계정으로 못 읽을 때, xxd가 SUID로 설정돼 있거나 sudo -l에 있으면 파일 읽기 프리미티브로 꺼낸다
- xxd가 root 소유 SUID 또는 sudo 허용 상태여야 하고, 셸 획득이 아닌 파일 읽기용 도구라는 점을 감안해 다른 권한 상승 경로와 병행한다

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

- `xxd /path/to/target`: 대상 파일의 16진수 덤프 출력
- `strings /path/to/target | less`: 사람이 읽을 수 있는 문자열만 추출

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

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
