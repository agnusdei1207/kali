# loop

- bash의 for·while 반복문, {1..10}과 seq 범위 표기, 산술 확장 $((...))을 정리하고 /dev/tcp로 1~1024 포트를 순차 스캔하는 실전 예시까지 담은 문서
- 대상 목록 전체를 하나씩 확인하는 열거 작업이나 nc·nmap 없이 포트를 훑어야 할 때 꺼낸다
- bash가 필요하고 /dev/tcp 스캔은 bash 내장 기능이라 별도 도구가 없어도 되지만, 범위가 크면 매우 느려 rustscan·nmap 같은 대안을 고려한다

## 개요

`for`와 `while`은 반복 작업의 기본이다. OSCP 풀이에서 루프는 "전체 열거", "반복 시도"에 꼭 쓴다.

## for 반복

```bash
#!/bin/bash
for i in {1..10};
do
    echo $i
done
```

- `{1..10}` : 1부터 10까지. `seq`를 써도 된다: `seq 1 10`.

## while 반복

```bash
#!/bin/bash
count=0
while [ $count -lt 10 ]; do
    echo "count: $count"
    count=$((count + 1))
done
```

- 조건이 거짓이 되면 끝난다. `while true`는 무한 루프다(필요할 때만).

## 실전 예시

```bash
#!/bin/bash
# 1~1024 포트를 순차적으로 스캔 (시간이 오래 걸리므로 느리다)
for port in {1..1024}; do
    (echo > /dev/tcp/10.10.10.10/$port) >/dev/null 2>&1 && echo "open: $port"
done
```

## 팁

- 대규모 순차 스캔은 시간이 오래 걸리므로, `rustscan`/`nmap` 같은 자동 도구를 쓰는 것이 낫다.
- 루프는 "전체를 끝까지" 확인할 때, 자동화 대상에서만 쓴다.
