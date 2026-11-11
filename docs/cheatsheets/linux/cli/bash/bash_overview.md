# bash_overview (bash 기초)

> 무엇: OSCP 공격 스크립트를 바로 짜는 데 필요한 bash 기초 — 셔뱅, 기본 출력, for/while 반복문, if 조건문, 함수, 파일·프로세스 제어(ls, ps, kill)만 뽑은 요약 문서
> 언제: 타깃에서 반복 작업을 자동화하는 짧은 스크립트를 작성할 때 먼저 참고하고, 세부 문법은 bash_syntax.md로 넘어간다
> 조건: bash와 리눅스 기본 유틸리티만 있으면 되고 별도 설치나 특별 권한은 필요 없다

## 개요

이 문서는 OSCP 공격에 필요한 bash 문법을 빠르게 익힌다.
자세한 설명은 `bash_syntax.md`를 참고하고, 여기서는 자주 쓰는 명령만 정리한다.

## 기본

```bash
#!/usr/bin/env bash
echo "hello"
```

## 반복문

```bash
#!/bin/bash
for i in {1..10};
do
    echo $i
done
```

## 조건문

```bash
#!/bin/bash
read name
if [ "$name" = "Stewart" ]; then
    echo "Welcome!"
else
    echo "no"
fi
```

## 함수

```bash
myfunc() {
    echo "called with: $1"
}
myfunc "argument"
```

## 파일/프로세스

```bash
ls -la /home
ps aux
kill -9 <PID>
```

## 실전 팁

- OSCP 시험에서는 bash를 빠르게 치는 능력이 성능을 좌우한다. 매일 30분씩 익히자.
- `set -e`는 오류로 종료하는 데 실용적이지만, 실험 중에는 붙여 두지 않는다.
