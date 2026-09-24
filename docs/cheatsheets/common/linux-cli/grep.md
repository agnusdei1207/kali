```bash
# 현재 디렉토리 및 하위 폴더에서 'flag' 키워드 대소문자 무시하고 검색
grep -iR flag .

# 특정 파일에서 'password' 키워드 포함된 줄과 줄 번호 출력
grep -n password config.php

# 재귀 검색 "tyler" 문자열 /var/log/ 파일 내부까지 다 검색
grep -iR tyler /var/log/

# 'nologin' 없는 줄만 출력
grep -v nologin /etc/passwd

# 정규표현식으로 user01, user99 등 검색
grep -E "user[0-9]{2}" users.txt

# 검색된 줄 이후 2줄 추가 출력
grep -A 2 error log.txt

# 검색된 줄 전후 2줄 추가 출력
grep -C 2 error log.txt

# 옵션 조합 예시: 대소문자 무시, 줄 번호, 재귀 검색
grep -inR keyword .
```

## 옵션별 설명

- -i (선택): 대소문자 구분 없이 검색
- -R (선택): 하위 디렉토리까지 재귀적으로 검색
- -n (선택): 결과에 줄 번호 표시
- -v (선택): 검색어가 없는 줄만 출력
- -E (선택): 확장 정규표현식 사용
- -A <숫자> (선택): 검색된 줄 이후 <숫자>줄 추가 출력
- -B <숫자> (선택): 검색된 줄 이전 <숫자>줄 추가 출력
- -C <숫자> (선택): 검색된 줄 전후 <숫자>줄 추가 출력

# grep 명령어 실전 예시 및 옵션 설명

## 기본 사용법

- `grep [옵션] <검색어> <파일명>`
- 파일명: .txt, .log 등 텍스트 파일

## 주요 옵션

- -i (선택): 대소문자 구분 없이 검색
- -R (선택): 하위 디렉토리까지 재귀적으로 검색
- -n (선택): 결과에 줄 번호 표시
- -v (선택): 검색어가 없는 줄만 출력
- -E (선택): 확장 정규표현식 사용
- -A <숫자> (선택): 검색된 줄 이후 <숫자>줄 추가 출력
- -B <숫자> (선택): 검색된 줄 이전 <숫자>줄 추가 출력
- -C <숫자> (선택): 검색된 줄 전후 <숫자>줄 추가 출력

## 실전 예시

### 1. 특정 키워드 검색

```bash
grep root /etc/passwd
```

- /etc/passwd 파일에서 'root' 포함된 줄 출력

### 2. 대소문자 무시

```bash
grep -i admin users.txt
```

- 'admin', 'Admin', 'ADMIN' 등 모두 검색

### 3. 줄 번호 포함

```bash
grep -n password config.php
```

- 'password' 포함된 줄과 줄 번호 출력

### 4. 하위 폴더 전체 검색

```bash
grep -R "flag" .
```

- 현재 디렉토리 및 하위 폴더에서 'flag' 검색

### 5. 특정 키워드 제외

```bash
grep -v "nologin" /etc/passwd
```

- 'nologin' 없는 줄만 출력

### 6. 정규표현식 사용

```bash
grep -E "user[0-9]{2}" users.txt
```

- user01, user99 등 패턴 검색

### 7. 검색된 줄 이후 2줄 추가 출력

```bash
grep -A 2 "error" log.txt
```

### 8. 검색된 줄 이전 2줄 추가 출력

```bash
grep -B 2 "error" log.txt
```

### 9. 검색된 줄 전후 2줄 추가 출력

```bash
grep -C 2 "error" log.txt
```

## 실전 팁

- 파일 확장자: .txt, .log, .conf 등 텍스트 파일에 사용
- 옵션 조합 가능: `grep -inR "keyword" .`
- 결과가 많을 때: `grep "keyword" file.txt | less`

필수/선택 옵션, 파라미터 타입 명확히 구분. OSCP 시험에서 바로 활용 가능.
