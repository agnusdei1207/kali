# Dreamhack - rev-basic-0 Writeup

## 1. 개요 및 분석 환경

- **플랫폼**: Dreamhack (Wargame - Reversing)
- **대상 바이너리**: `rev-basic-0` (x86-64 PE executable / Linux WSL2 분석)
- **분석 도구**: `strings`, `gdb`, `binutils`

```bash
# Ubuntu 컨테이너/환경 준비
winpty docker run -it --name dreamhack_env ubuntu:24.04 /bin/bash
apt update && apt install -y binutils gdb
```

---

## 2. 정적 분석 (Static Analysis)

### Strings 문자열 추출
바이너리 내부 문자열을 추출하여 비교 로직 및 하드코딩된 플래그 여부를 확인합니다.

```bash
root@c627f2c198f6:/tmp# strings rev-basic-0 | grep -C 5 Correct
```

**출력 결과**:
```text
$(3
t$0H
Compar3_the_str1ng
Input :
%256s
Correct
Wrong
RSDS
C:\Users\user\source\repos\reversing-wargame\x64\Release\chall0.pdb
GCTL
.text$mn
```

- 사용자 입력(`Input : %256s`) 직후 `Correct` / `Wrong` 분기문이 존재합니다.
- 비교 대상 문자열로 추정되는 `Compar3_the_str1ng`가 바로 직전에 하드코딩되어 노출됩니다.

---

## 3. 동적 검증 및 플래그 획득

바이너리를 실행하고 추출한 문자열을 입력하여 일치 여부를 검증합니다.

```bash
root@c627f2c198f6:/tmp# ./rev-basic-0
Input : Compar3_the_str1ng
Correct
```

- **정답 플래그**: `DH{Compar3_the_str1ng}`
