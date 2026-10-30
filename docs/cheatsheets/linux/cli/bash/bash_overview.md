# bash_overview (bash 기초)

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
