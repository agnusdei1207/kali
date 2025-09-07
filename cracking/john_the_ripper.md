# 크래킹 파일은 저장 시 .hash 로 저장하기 -> .txt 로 하면 일부 줄바꿈 또는 인코딩 문제 발생

echo '$P$B0jO/cdGOCZhlAJfPSqV2gVi2pb7Vd/' > think.hash

# 해시가 어떤 포맷인지 식별하는 방법

| 해시 예시           | 포맷          | 설명                  |
| ------------------- | ------------- | --------------------- |
| `$P$B...`           | `phpass`      | WordPress, phpBB 계열 |
| `$1$...`            | `md5crypt`    | Linux MD5             |
| `$6$...`            | `sha512crypt` | Linux SHA512          |
| `$2y$10$...`        | `bcrypt`      | bcrypt 해시           |
| `5f4dcc3b5aa765...` | `raw-md5`     | 일반 MD5              |
| `aad3b435b5...:...` | `nt`          | NTLM 해시 (Windows)   |

좋습니다. 이건 WordPress 사용자 테이블(`wp_users`)에서 추출한 것으로 보이며, 각 유저의 사용자명과 `phpass` 형식의 패스워드 해시가 포함되어 있습니다.

---

## John the Ripper에서 크랙 가능한 포맷으로 변환

John은 기본적으로 `username:hash` 형식을 인식합니다. 그래서 다음처럼 텍스트 파일을 만들어야 합니다:

```text
think:$P$B0jO/cdGOCZhlAJfPSqV2gVi2pb7Vd/
gege:$P$BsIY1w5krnhP3WvURMts0/M4FwiG0m1
diego:$P$BWFBcbXdzGrsjnbc54Dr3Erff4JPwv1
xavi:$P$BvcalhsCfVILp2SgttADny40mqJZCN/
```

---

## ✅ 저장 방법

```bash
# 'EOF' 작은 따옴표로 처리하여 $ 읽게끔 수정
cat <<'EOF' > users.hash
think:$P$B0jO/cdGOCZhlAJfPSqV2gVi2pb7Vd/
gege:$P$BsIY1w5krnhP3WvURMts0/M4FwiG0m1
diego:$P$BWFBcbXdzGrsjnbc54Dr3Erff4JPwv1
xavi:$P$BvcalhsCfVILp2SgttADny40mqJZCN/
EOF
```

---

## ✅ 크랙 명령어

₩₩

```bash
john --format=phpass --wordlist=/usr/share/wordlists/rockyou.txt users.hash

# 제공 포멧 확인
john --list=formats
# 해시 유형 감지
john --show ~/John-the-Ripper-The-Basics/Task04/hash1.txt

```

진행 중 상태 보기:

```bash
john --status
```

완료 후 결과 확인:

```bash
john --show --format=phpass users.hash
```

---

# 해시 크랙 시 전체 행 입력 필요 여부 정리

| 구분              | 내용                                                                                                                                               |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| 전체 행 입력 필요 | 특정 해시(예: Kerberos AS-REP) 등은 해시 문자열 전체(버전, 사용자, 도메인, 해시값 포함)를 넣어야 정확히 인식 및 크랙 가능                          |
| 이유              | 해시마다 메타정보(버전, 사용자명, 도메인, 솔트 등)가 포함되어 있어 일부만 넣으면 도구가 해시 포맷을 인식하지 못함                                  |
| 실제 사례         | - Kerberos AS-REP 해시: `$krb5asrep$버전$사용자@도메인:암호화부분:추가정보` 전체 필요<br>- NTLM 해시: 사용자명, 도메인, 해시값 전체 입력 요구 가능 |
| 도구별 특성       | - John the Ripper, hashcat 등은 표준 포맷 전체 입력 요구<br>- hashid 같은 도구는 일부만 인식 시 'Unknown hash' 결과                                |

---

# 요약

- 단순 해시는 해시값만 입력 가능
- 복합 해시는 전체 행 전체 문자열 입력 필수
- 전체 행 입력이 안 되면 크랙 불가능하거나 도구가 인식 불가

---

```bash
# =================== 설치 방법 ===================
sudo apt update
sudo apt install john -y

# John은 $6$ 같은 접두사를 보고 --format=sha512crypt 없이도 알아서 처리할 수 있어요.

# 최신 jumbo 버전 설치 (더 많은 해시 포맷 지원)
git clone https://github.com/openwall/john.git
cd john/src
./configure && make -s clean && make -sj4

# =================== 기본 사용법 ===================

# 1. 패스워드 크래킹 (기본)
john 해시파일

# 2. 특정 포맷 지정
john --format=포맷명 해시파일
# 예: SHA512 (리눅스 /etc/shadow)
john --format=sha512crypt 해시파일
# 예: NTLM (윈도우)
john --format=nt 해시파일

# 3. 워드리스트 사용
john --wordlist=/usr/share/wordlists/rockyou.txt 해시파일

# 4. 규칙 적용 (단어 변형)
john --rules --wordlist=/usr/share/wordlists/rockyou.txt 해시파일

# 5. 이미 발견된 패스워드 표시
john --show 해시파일

# =================== 특정 파일 대상 크래킹 ===================

# 1. /etc/shadow 크래킹
sudo john /etc/shadow

# 2. /etc/shadow와 /etc/passwd 합치기 (unshadow)
sudo unshadow /etc/passwd /etc/shadow > hash.txt
john hash.txt

# 3. 윈도우 SAM 파일 크래킹
john --format=nt sam.txt

# 4. 해시 식별 (해시 유형 자동 탐지)
john --identify 해시파일

# =================== 특정 해시 타입 예시 ===================

# 1. 웹 어플리케이션 해시
# MD5
john --format=raw-md5 웹해시파일
# SHA1
john --format=raw-sha1 웹해시파일
# bcrypt
john --format=bcrypt 웹해시파일

# 2. 압축 파일 (zip, rar 등)
# ZIP 파일
zip2john 암호화된.zip > zip.hash
john zip.hash
# RAR 파일
rar2john 암호화된.rar > rar.hash
john rar.hash

# 3. 문서 파일 (pdf, office 등)
# PDF 파일
pdf2john 암호화된.pdf > pdf.hash
john pdf.hash
# MS Office 문서
office2john 암호화된.docx > office.hash
john office.hash

# =================== 고급 기능 ===================

# 1. 세션 저장 및 복구
john --session=세션명 해시파일
# 중단된 세션 복구
john --restore=세션명

# auto save point
~/.john/john.rec

# search formats
john --list=formats | grep -i md5

# MD5 example
john --format=Raw-MD5  --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --fork=4
john --show --format=raw-md5 hash.txt

# 2. 특정 사용자만 크래킹
john --users=사용자명 해시파일

# 3. 속도 조절 (멀티코어 활용)
john --fork=4 해시파일

# 4. 마스크 공격 (패턴 기반)
john --mask='?d?d?d?d?d?d' 해시파일  # 6자리 숫자
john --mask='?l?l?l?l?d?d?d?d' 해시파일  # 4개 소문자 + 4개 숫자

# 5. 브루트포스 (무차별 대입)
john --incremental 해시파일
john --incremental=digits 해시파일  # 숫자만

# =================== OSCP 실전 팁 ===================

# 1. 중요 포맷 (자주 만남)
# Linux: sha512crypt (기본), sha256crypt, md5crypt
# Windows: nt (NTLM 해시)
# 웹앱: raw-md5, raw-sha1, bcrypt, mysql, mysql-sha1
# 데이터베이스: oracle, mysql, mssql, postgresql

# =================== 포맷 옵션 확인 ===================

# 1. 지원하는 모든 포맷 보기
john --list=formats

# 2. 주요 포맷 예시 (--format= 뒤에 붙임)
# 리눅스 계열
sha512crypt    # 최신 리눅스 기본 (/etc/shadow)
sha256crypt    # RHEL, CentOS 6 이상
md5crypt       # 구형 리눅스
des            # 아주 오래된 유닉스

# 윈도우 계열
nt             # NTLM 해시 (Windows NT 이상)
lm             # LM 해시 (구형 윈도우)
netlm, netntlm # Net-NTLM 해시 (NTLM 네트워크 인증)

# 웹 해시
raw-md5        # 일반 MD5
raw-sha1       # 일반 SHA1
raw-sha256     # 일반 SHA256
raw-sha512     # 일반 SHA512
bcrypt         # BCrypt (많은 웹앱에서 사용)
phpass         # PHPass (PHP, WordPress, Drupal 등)

# 데이터베이스
mysql          # MySQL v3.23
mysql-sha1     # MySQL v4.1+
oracle         # Oracle 해시
oracle11       # Oracle 11g 해시
mssql          # MS-SQL
postgresql     # PostgreSQL

# 어플리케이션/서비스
ssh            # SSH 키 패스프레이즈
sshng          # SSH 키 (더 새로운 버전)
krb5           # Kerberos 해시
wpa            # WPA/WPA2 PSK 해시

# 3. 포맷 사용 확인 명령어
john --list=format-details --format=sha512crypt
john --test=10 --format=sha512crypt   # 속도 테스트

# =================== 해시 변환 도구 ===================

# 1. 다양한 파일 변환 유틸리티
zip2john, rar2john, office2john, pdf2john  # 압축/문서 파일
ssh2john       # SSH 키
keepass2john   # KeePass 데이터베이스
hccap2john     # WPA 캡처 파일

# 2. 해시 식별 및 변환
hashid 해시값          # 해시 타입 식별
hash-identifier 해시값 # 해시 타입 식별
```
