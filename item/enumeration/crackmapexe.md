## 💥 CrackMapExec SMB enumeration -> 애는 버전 호환 이슈 많음 -> enum4linux, smbmap 위주로 사용하기

### 1\. ⚙️ 기본 사용법

```bash

sudo apt install crackmapexec
# 의존성 업데이트
sudo apt upgrade crackmapexec impacket-scripts python3-impacket
# 기본 문법 (프로토콜 지정 필수)
crackmapexec smb <대상IP/CIDR/파일> [인증 옵션] [모듈/기능 옵션]
```

-----

### 2\. 🔑 인증 옵션 (Credential Options)

| 문법 | 설명 | OSCP 활용 |
| :--- | :--- | :--- |
| `crackmapexec smb 10.10.10.10` | **널 세션 (Null Session) 시도** (사용자/비밀번호 없이 익명 접근 시도). | 가장 먼저 시도하는 익명 열거 단계. |
| `-u <user> -p <pass>` | 단일 사용자 이름과 비밀번호로 인증. | 확보한 유효한 자격 증명 사용. |
| `-u <user> -P <pass.txt>` | 단일 사용자에 대해 **비밀번호 목록 파일** 대입 (Brute-force). | 특정 계정의 비밀번호 크래킹. |
| `-U <user.txt> -p <pass>` | **사용자 목록 파일**에 대해 단일 비밀번호 대입 (**Credential Spraying**). | 다수 계정에 쉬운 비밀번호 테스트. |
| `-U <user.txt> -P <pass.txt>` | 사용자 목록과 비밀번호 목록을 조합하여 테스트. | 일반적인 무차별 대입 공격. |
| `--local-auth` | 로컬 계정 인증 시도 (도메인이 아닌 로컬 계정). | 도메인 컨트롤러가 아닌 일반 서버 타겟 시. |
| `-u <user> -H <NTLM해시>` | **Pass-the-Hash (PtH)** 공격. NTLM 해시만으로 인증. | 덤프된 NTLM 해시를 활용한 접속 시도. |

-----

### 3\. 🎯 핵심 열거 옵션 (Enumeration & Module Options)

CME는 모듈(`-M`)이나 단축 옵션을 통해 다양한 정보를 수집합니다.

| 옵션 | 설명 | 기능 |
| :--- | :--- | :--- |
| **`--shares`** | 대상 시스템의 모든 **SMB 공유 폴더 목록**과 **접근 가능한 권한**을 나열합니다. | `smbmap`의 기본 기능과 유사. 가장 필수적인 열거 옵션. |
| **`--users`** | SMB를 통해 **로컬 사용자 목록**을 열거합니다. | 권한 상승 전 사용자 계정 정보 수집. |
| **`--rid-brute`** | **RID Brute-force 공격**을 통해 유효한 사용자 이름과 그룹을 열거합니다. | 사용자 목록을 얻는 강력한 수단. |
| **`--pass-pol`** | **암호 정책** (최소 길이, 복잡성 등)을 열거합니다. | Brute-force 공격 전략 수립에 활용. |
| **`-M <module>`** | **내장된 모듈**을 실행합니다. (예: `-M spider`로 파일 탐색, `-M sam`으로 SAM 덤프 시도) | 특정 작업을 수행하기 위한 확장 기능 사용. |

-----

### 4\. 📝 사용 예시 (Practical Examples)

#### 예시 1: 서브넷 전체 Null Session 시도 및 공유 열거

```bash
# 10.10.10.0/24 서브넷 전체를 스캔하고, Null Session으로 접속 가능한 공유 목록을 확인
crackmapexec smb 10.10.10.0/24 --shares
```

#### 예시 2: 자격 증명 스프레이 (Credential Spraying)

```bash
# users.txt 파일의 모든 사용자에게 단일 비밀번호 'Winter2024!'를 대입하여 유효 계정 찾기
crackmapexec smb 10.10.10.10 -U users.txt -p 'Winter2024!'
```

#### 예시 3: Pass-the-Hash (PtH) 공격

```bash
# administrator 사용자의 NTLM 해시를 사용하여 인증 시도
crackmapexec smb 10.10.10.10 -u administrator -H 'a9fdfa038c4b75ebc76dc855dd74f0da' --shares
```

#### 예시 4: RID Brute-force를 이용한 사용자 열거

```bash
# 획득한 유효 자격 증명으로 접속 후, RID Brute-force 모듈 실행
crackmapexec smb 10.10.10.10 -u user -p pass --rid-brute
```

#### 예시 5: 파일 목록 재귀적 확인 (Spider 모듈)

```bash
# 유효 자격 증명으로 접속 후, Spider 모듈을 사용하여 'Share' 공유 폴더 내부 파일 목록 확인
crackmapexec smb 10.10.10.10 -u user -p pass -M spider -o SHARE=Share
```

-----

### 5\. 💡 결과 해석 및 결합 활용 팁

| 필드 | 의미 | 활용 팁 |
| :--- | :--- | :--- |
| **P** (Pwned) | 유효한 자격 증명으로 접속에 성공함 (`+` 표시). | 이 계정을 다른 서비스(SSH, RDP 등)에 재사용 시도 (Pass-the-Hash 가능성). |
| **Shares** | 열거된 공유 폴더와 익명/인증된 사용자의 권한. | `READ/WRITE` 권한을 가진 공유를 찾아 **셸 파일 업로드** 경로로 활용. |
| **OS** | 대상 시스템의 운영체제 정보. | 익스플로잇 선택 및 권한 상승 전략 수립에 중요. |
| **SID** | Windows 시스템의 보안 식별자. | RID Brute-force의 시작점이나 도메인 정보 확인에 활용. |

#### 결합 활용 팁

```bash
# Nmap 출력 파일에서 SMB 포트가 열린 IP만 추출하여 CME로 자격 증명 스프레이
cat nmap_scan.gnmap | grep "445/open" | awk '{print $2}' > smb_targets.txt
crackmapexec smb -f smb_targets.txt -U users.txt -p 'Fall2024$'

# 유효한 크리덴셜(user:pass)을 얻은 후, CME를 사용하여 RDP 포트가 열려있는지 확인
crackmapexec rdp 10.10.10.0/24 -u user -p pass
```