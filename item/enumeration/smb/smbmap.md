# SMBMap 치트시트 -> OSCP 사용 가능


## 기본 사용법

```bash
sudo apt install smbmap
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
# 안전하게 비밀번호 파싱
smbmap -d <도메인> -u <사용자명> -p '<비밀번호>' -H 10.10.10.10

# 패스워드 해시 사용(Pass-the-Hash)
smbmap -u <사용자명> -p <NTLM해시> -H 10.10.10.10

```
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


### 권한 설명

- `NO ACCESS`: 접근 불가
- `READ ONLY`: 읽기만 가능
- `READ, WRITE`: 읽기/쓰기 가능
- `DISK_OPERATE`: 모든 권한

> 결과해석

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

## 결합 활용 팁
```bash
# nmap으로 열린 SMB 포트 확인 후 SMBMap 실행
ports=$(nmap -p 139,445 10.10.10.0/24 --open -oG - | grep "/open" | cut -d" " -f2)
for ip in $ports; do smbmap -H $ip; done

# 사용자 목록과 패스워드 목록으로 SMB 접속 시도
for u in $(cat users.txt); do for p in $(cat pass.txt); do echo "Testing $u:$p"; smbmap -u "$u" -p "$p" -H 10.10.10.10; done; done
```


> 결과 해석

```
[+] IP: 10.65.165.138:445       Name: 10.65.165.138             Status: NULL Session
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        anonymous                                               READ ONLY       Skynet Anonymous Share
        milesdyson                                              NO ACCESS       Miles Dyson Personal Share
        IPC$                                                    NO ACCESS       IPC Service (skynet server (Samba, Ubuntu))
[*] Closed 1 connections       

```

```bash
# -s anonymous: 탐색할 공유 폴더 지정
# -r '': 공유 폴더의 루트 (Root)에서부터 재귀 탐색 시작
# --depth 10: 탐색 깊이를 지정 (선택 사항, 깊이 10까지 탐색)
smbmap -H 10.65.165.138 -u anonymous -s anonymous -r '' --depth 5

```
[+] IP: 10.65.165.138:445       Name: 10.65.165.138             Status: NULL Session
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        anonymous                                               READ ONLY       Skynet Anonymous Share
        ./anonymous
        dr--r--r--                0 Fri Nov 27 01:04:00 2020    .
        dr--r--r--                0 Tue Sep 17 16:20:17 2019    ..
        fr--r--r--              163 Wed Sep 18 12:04:59 2019    attention.txt
        dr--r--r--                0 Wed Sep 18 13:42:16 2019    logs
        ./anonymous//logs
        dr--r--r--                0 Wed Sep 18 13:42:16 2019    .
        dr--r--r--                0 Fri Nov 27 01:04:00 2020    ..
        fr--r--r--                0 Wed Sep 18 13:42:13 2019    log2.txt
        fr--r--r--              471 Wed Sep 18 13:41:59 2019    log1.txt
        fr--r--r--                0 Wed Sep 18 13:42:16 2019    log3.txt
        milesdyson                                              NO ACCESS       Miles Dyson Personal Share
        IPC$                                                    NO ACCESS       IPC Service (skynet server (Samba, Ubuntu))
[*] Closed 1 connections                                                                                                     
                         

```bash
# --download '<공유명>/<경로>' 형식 사용
smbmap -H 10.65.165.138 -u anonymous --download 'anonymous/attention.txt'
```