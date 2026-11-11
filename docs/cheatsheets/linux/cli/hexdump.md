# hexdump

> 무엇: 파일을 16진수+ASCII(-C)로 덤프해 내부 구조를 들여다보는 hexdump의 옵션(-C, -v, -e, -s, -n)과 예제를 정리한 문서
> 언제: /etc/shadow 해시 덤프 확인, 바이너리·파일 헤더 분석, 인코딩 깨진 문자 확인처럼 바이트 단위 검토가 필요할 때 쓰고 grep과 조합한다
> 조건: Debian/Ubuntu는 bsdmainutils, RHEL 계열은 util-linux 패키지 설치가 필요하다(macOS는 brew)

### 1️⃣ 설치

```bash
# Debian/Ubuntu
sudo apt install bsdmainutils

# RedHat/CentOS
sudo yum install util-linux

# MacOS
brew install bsdmainutils
```

---

### 2️⃣ 옵션 핵심

| 옵션      | 설명                    |
| --------- | ----------------------- |
| -C        | 16진수 + ASCII 보기     |
| -v        | 반복 라인 생략하지 않음 |
| -e '...'  | 출력 포맷 지정          |
| -s offset | 시작 바이트 지정        |
| -n count  | 출력 바이트 수 지정     |

---

### 3️⃣ 기본 사용

```bash
hexdump file            # 기본 8바이트 단위 16진수 출력
hexdump -C file         # 16진수 + ASCII 출력 (추천)
```

---

### 4️⃣ 예제

```bash
# 파일 전체 덤프
hexdump -C file.bin

# 1바이트씩 16진수 출력
hexdump -v -e '1/1 "%02X "' file.bin

# 10바이트부터 20바이트만 출력
hexdump -s 10 -n 20 -C file.bin

# 덤프 결과를 파일로 저장
hexdump -C file.bin > dump.txt
```

---

### 5️⃣ 활용

- 펜테스트: /etc/shadow 해시 분석, 바이너리 확인
- 포렌식: 파일 헤더/악성코드 확인
- 디버깅: 깨진 문자/인코딩 확인
#### grep 결합 가능

```bash
hexdump -C file.bin | grep "414243"   # 16진수 검색
```

---

### 6️⃣ 요약

- 핵심 목적: 파일 내부 구조 16진수 시각화
- ASCII와 함께 보면 텍스트/바이너리 쉽게 확인 가능
- 옵션 `-C`, `-v`, `-e`, `-s`, `-n`만 기억하면 대부분의 작업 가능
