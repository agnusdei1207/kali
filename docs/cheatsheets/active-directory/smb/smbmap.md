# smbmap으로 SMB 공유 권한 매핑

- smbmap — SMB 공유별 READ/WRITE 권한을 한 번에 매핑하는 도구. 파일 검색·다운로드·업로드, 명령 실행(-x)까지 지원하며 smbclient보다 권한 요약이 한눈에 들어온다.
- 공유 목록과 접근 권한을 빠르게 정리할 때, ADMIN 권한 공유를 찾아 명령 실행(-x)을 시도할 때, 재귀적으로 파일 목록을 뽑아 자료·설정 파일을 수집할 때.
- Kali는 apt install smbmap, 또는 pip install smbmap. 대상 445 포트 접근 필요.

## 기본 명령어 구조

```bash
smbmap -H 10.10.10.10 -u user -p 'Passw0rd' -d CORP
```

- `-H`: 대상 IP 또는 FQDN. `-u`/`-p`/`-d`는 각각 사용자명·패스워드·도메인이다.
- `-p`는 패스워드 대신 NTLM 해시(LMHASH:NTHASH 형식)도 받는다.
- `-u`를 생략하면 null session으로 접속을 시도하며, `-u ''`로도 익명 접속을 시도할 수 있다.

## 권한 요약과 나열

```bash
smbmap -H 10.10.10.10 -u user -p 'Passw0rd'             # 공유 + 권한 요약
smbmap -H 10.10.10.10 -u user -p 'Passw0rd' -L          # 로컬 디스크 나열(ADMIN 권한 필요)
smbmap -H 10.10.10.10 -u user -p 'Passw0rd' -q          # READ/WRITE 공유만 표시
smbmap -H 10.10.10.10 --host-file hosts.txt -u user -p 'Passw0rd'
```

- 출력은 Disk / Permissions / Comment 형태로 READ, WRITE, READ ONLY, NO ACCESS로 표시된다. WRITE가 붙으면 업로드 지점이고, READ/WRITE 공유에는 ADMIN!!! 표시가 붙기도 한다.
- `-L`: 공유가 아니라 로컬 디스크(C:\, D:\) 목록을 보여주는 기능으로 관리자 권한이 필요하다.
- `-q`: NO ACCESS 공유를 감춰 결과를 깔끔하게 만든다.

## 재귀 탐색과 파일 수집

```bash
smbmap -H 10.10.10.10 -u user -p 'Passw0rd' -r            # 모든 공유를 재귀적으로 나열
smbmap -H 10.10.10.10 -u user -p 'Passw0rd' -r 'Users'    # 특정 공유·경로만 재귀
smbmap -H 10.10.10.10 -u user -p 'Passw0rd' -r --depth 2  # 탐색 깊이 제한
smbmap -H 10.10.10.10 -u user -p 'Passw0rd' -r -A '(password|config).*\.xml'
```

- `-r`은 하위 디렉터리까지 파일명과 크기를 나열한다. `--depth`로 깊이를 제한한다.
- `-A`: 정규식 패턴에 맞는 파일을 재귀 탐색(-r) 중 자동으로 내려받는다.

## 명령 실행

```bash
smbmap -H 10.10.10.10 -u user -p 'Passw0rd' -x 'ipconfig /all'
smbmap -H 10.10.10.10 -u user -p 'Passw0rd' -x 'whoami' --mode psexec
```

- `-x`: 대상에서 명령을 실행한다. 기본은 WMI 방식이고 `--mode psexec`으로 svcctl 파이프(PsExec식) 실행도 가능하다. 관리자 권한 자격증명이 필요하다.

## 실전 예시

```bash
# 익명 접속으로 열려 있는 공유 확인
smbmap -H 10.10.10.10

# 결과를 파일로 저장해 여러 호스트 일괄 매핑
smbmap --host-file hosts.txt -u user -p 'Passw0rd' -g smbmap_out.txt
```

## 팁·트러블슈팅

1. 모든 공유가 NO ACCESS면 자격증명이 유효하지 않은 것이다. 도메인 지정(-d)을 빠뜨린 경우에도 이렇게 보인다.
2. NO ACCESS여도 IPC$는 null session 용도로 열려 있는 상태가 정상이므로, 이를 근거로 익명 접속이 성공했다고 판단하지 않는다.
3. -r 결과가 너무 크면 --exclude IPC$와 --depth를 붙여 탐색 범위를 좁힌다.
