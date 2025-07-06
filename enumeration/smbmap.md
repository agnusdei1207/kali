# SMBMap 치트시트 -> OSCP 사용 불가

## 기본 사용법

```bash
# 기본 문법
smbmap -H <대상IP/호스트명> [옵션]
```

## 인증 옵션

```bash
# 널 세션(anonymous) 접근 시도
smbmap -H 10.10.10.10

# 사용자 인증정보 사용
smbmap -u <사용자명> -p <비밀번호> -H 10.10.10.10

# 도메인 사용자로 인증
smbmap -d <도메인> -u <사용자명> -p <비밀번호> -H 10.10.10.10

# 패스워드 해시 사용(Pass-the-Hash)
smbmap -u <사용자명> -p <NTLM해시> -H 10.10.10.10
```

## 주요 옵션

```bash
# 모든 드라이브 나열
smbmap -H 10.10.10.10 --drive-type ALL

# 공유에서 파일 검색
smbmap -H 10.10.10.10 -R <공유명> --depth 5

# 특정 파일 검색 (재귀)
smbmap -H 10.10.10.10 -R <공유명> -A <파일패턴> --depth 10

# 특정 파일 다운로드
smbmap -H 10.10.10.10 -R <공유명> --download '<경로>'

# 특정 파일 업로드
smbmap -H 10.10.10.10 --upload '<로컬파일경로>' '<원격경로>'

# 명령 실행 (관리자 권한 필요)
smbmap -H 10.10.10.10 -u <사용자명> -p <비밀번호> -x 'ipconfig /all'

# 출력 포맷 지정
smbmap -H 10.10.10.10 -g # grep 가능한 포맷으로 출력
```

## 사용 예시

### 1. 기본 공유 나열

```bash
smbmap -H 10.10.10.10
```

### 2. 사용자 인증으로 공유 나열

```bash
smbmap -u administrator -p 'P@ssw0rd!' -H 10.10.10.10
```

### 3. 특정 공유 내 파일 및 폴더 확인

```bash
smbmap -H 10.10.10.10 -u administrator -p 'P@ssw0rd!' -R 'C$'
```

### 4. 공유 내 password 문자열이 포함된 파일 검색

```bash
smbmap -H 10.10.10.10 -u administrator -p 'P@ssw0rd!' -R 'C$' -A 'password' --depth 10
```

### 5. 도메인 환경에서 사용

```bash
smbmap -d THM-AD -u administrator -p 'P@ssw0rd!' -H 10.10.10.10
```

### 6. Pass-the-Hash 공격

```bash
smbmap -u administrator -p 'aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' -H 10.10.10.10
```

## 결과 해석

```
[+] IP: 10.10.10.10:445	Name: target.local
    Disk                 Permissions	    Comment
    ----                 -----------	    -------
    ADMIN$               NO ACCESS	    원격 관리용
    C$                   NO ACCESS	    기본 공유
    IPC$                 READ ONLY	    원격 IPC
    NETLOGON             READ ONLY	    로그온 서버 공유
    SYSVOL              READ ONLY	    로그온 서버 공유
    Users                READ ONLY	    사용자 프로필 디렉토리
```

### 권한 설명

- `NO ACCESS`: 접근 불가
- `READ ONLY`: 읽기만 가능
- `READ, WRITE`: 읽기/쓰기 가능
- `DISK_OPERATE`: 모든 권한

## 결합 활용 팁

```bash
# nmap으로 열린 SMB 포트 확인 후 SMBMap 실행
ports=$(nmap -p139,445 10.10.10.0/24 --open -oG - | grep "/open" | cut -d" " -f2)
for ip in $ports; do smbmap -H $ip; done

# 사용자 목록과 패스워드 목록으로 SMB 접속 시도
for u in $(cat users.txt); do for p in $(cat pass.txt); do echo "Testing $u:$p"; smbmap -u "$u" -p "$p" -H 10.10.10.10; done; done
```
