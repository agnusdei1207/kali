# smbclient로 SMB 공유 접근

- smbclient — Samba의 FTP식 SMB 클라이언트. -L로 공유 목록을 조회하고 대화형 프롬프트에서 get/put으로 파일을 주고받는다. enum4linux·smbmap이 의존하는 기본 도구다.
- 공유 목록을 나열하고 파일을 다운로드·업로드할 때, NTLM 해시만으로 인증(Pass-the-Hash)해 접속할 때, 익명(null session) 접속 허용 여부를 점검할 때.
- Kali 기본 포함(samba 패키지). 대상 445(또는 139) 포트 접근 가능 필요.

## 공유 목록 조회

```bash
smbclient -L //10.10.10.10 -U 'user%Passw0rd'
smbclient -L //10.10.10.10 -N
```

- `-L`: 대상이 노출하는 공유 목록을 조회한다. `-U user%password` 형식으로 자격증명을 넣는다.
- `-N`: 패스워드 없이(no password) 접속한다. Disk 라벨의 공유가 열리면 익명 접속이 허용된 것이다.

## 공유 접속과 대화형 명령

```bash
smbclient //10.10.10.10/share -U 'user%Passw0rd'
```

```text
smb: \> ls                       # 현재 공유의 파일 목록
smb: \> cd folder; ls
smb: \> get backup.zip           # 파일 다운로드
smb: \> put shell.aspx           # 파일 업로드
smb: \> recurse; prompt; mget *  # 하위 폴더 전체 다운로드
smb: \> du                       # 공유 총 용량
smb: \> quit
```

- `recurse; prompt`: 재귀 모드로 바꾸고 mget/mput의 확인 질문을 끈다.
- `get`/`put`은 FTP 명령과 같은 감각이고, 로컬 파일명을 바꿔 저장하려면 `get 원격 로컬` 형태로 쓴다.

## Pass-the-Hash

```bash
smbclient //10.10.10.10/share -U 'administrator' --pw-nt-hash
# 패스워드 프롬프트에 NTLM 해시(LMHASH:NTHASH) 입력
```

- `--pw-nt-hash`: 입력받은 패스워드를 NT 해시로 해석한다. secretsdump 등으로 뽑은 NTLM 해시를 그대로 붙여넣으면 된다.

## 실전 예시

```bash
# 접속 후 즉시 명령 실행(-c), 도메인·자격증명 포함
smbclient //10.10.10.10/users -U 'CORP\user%Passw0rd' -c 'ls; cd desktop; get flag.txt'

# 해시로 공유 목록만 확인
smbclient -L //10.10.10.10 -U 'administrator' --pw-nt-hash

# 포트 지정(445 대신 139 사용 환경)
smbclient -L //10.10.10.10 -p 139 -U 'user%Passw0rd'
```

- `-c`: 접속 후 실행할 명령을 인자로 넘겨 대화형 없이 결과만 뽑는다.

## 팁·트러블슈팅

1. NT_STATUS_ACCESS_DENIED는 공유 접근 권한 문제, NT_STATUS_LOGON_FAILURE는 자격증명 오류다. 먼저 -L 목록부터 다시 확인한다.
2. 익명 접속이 IPC$에서만 성공하면 공유 열거는 막혀 있지만 rpcclient로 RID 열거가 가능할 수 있으니 두 도구를 같이 돌린다.
3. 파일명에 공백이 많으면 mget 대신 -c로 명령을 스크립트화하는 편이 실수가 적다.
