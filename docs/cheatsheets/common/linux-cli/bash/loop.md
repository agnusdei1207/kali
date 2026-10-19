# loop

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
- 모든 시도는 합법적인 대상(본인 소유·허가받은 시스템)에서만 실행한다.
