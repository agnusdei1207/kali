# find

## 개요

파일 시스템 탐색의 기본 명령. OSCP 정찰 단계에서 가장 자주 쓰인다.

## 사용법

```bash
# 특정 이름의 파일을 찾는다
find / -name "*.txt" 2>/dev/null

# 특정 이름의 파일을 찾고 출력
find / -name "49216.py" 2>/dev/null
```

## 자주 쓰는 조합

```bash
# 최근 7일 이내 수정된 파일을 찾는다
find / -mtime -7 2>/dev/null

# 특정 사용자의 홈 디렉터리만
find /home -user root 2>/dev/null

# 결과를 파일로 남긴다
find / -name "*.log" > /tmp/found.log
```

## 실전 팁

- 출력이 너무 길면 `head`/`grep`으로 좁힌다.
- 대상이 컨테이너이면 `/` 전체가 아니라 `/home`, `/var`, `/opt`부터 확인한다.
- `find` 결과는 노트(05-progress-tracker)에 반드시 적는다.

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
- 해당 도구의 공식 문서는 --help를 참조하여 추가 옵션을 확인한다.
- 테스트 결과를 스크린샷으로 남겨 증적 자료로 활용한다.
- 유사한 취약점이 다른 머신에도 있는지 확인한다.
