# if

- bash의 if 조건 분기와 [ ] 테스트 연산자(문자열 =/!=, 정수 -gt, 파일 -f/-d/-r/-x)를 정리한 문서
- 스크립트에서 "파일이 존재하면", "로그인에 성공하면" 같은 분기가 필요할 때 loop.md의 반복문과 짝지어 쓴다
- bash 셸만 있으면 되고, 조건식의 대괄호 안 공백과 변수 따옴표를 빠뜨리면 의도와 다르게 동작한다

## 개요

`if`는 조건 분기의 기본이다. 반복문(for/while)과 함께 자주 사용한다.

## 사용법

```bash
#!/bin/bash
echo "Please enter your name first:"
read name

if [ "$name" = "Stewart" ]; then
    echo "Welcome Stewart! Here is the secret: THM_Script"
else
    echo "Sorry! You are not authorized to access the secret."
fi
```

## 비교 연산자

| 표현 | 의미 |
|------|------|
| `[ "$a" = "$b" ]` | 문자열 비교 (=) |
| `[ "$a" != "$b" ]` | 문자열 불일치 |
| `[ "$a" -gt 10 ]` | 정수 비교 (숫자) |
| `[ -f file ]` | 파일 존재 |
| `[ -d dir ]` | 디렉터리 존재 |
| `[ -r file ]` | 읽기 가능 |
| `[ -x file ]` | 실행 가능 |

## 실전 예시

```bash
#!/bin/bash
count=0
for file in /home/user/*.log; do
    if [ -f "$file" ]; then
        count=$((count + 1))
    fi
done
echo "found $count files"
```

## 주의

- `=` 대신 `==`를 쓰는 셸도 있지만 bash에서는 `=`가 맞다.
- 공백/따옴표를 빠뜨리면 조건이 의도와 다르게 동작한다.
