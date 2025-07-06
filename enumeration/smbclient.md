# SMBClient

개념: SMB 파일 공유에 접속해 파일 탐색 가능 (리눅스용 Windows Explorer 느낌)

## 1. 설치

```bash
# Kali Linux
sudo apt update
sudo apt install smbclient -y

# macOS
brew install samba

# Linux (Ubuntu/Debian)
sudo apt update
sudo apt install smbclient -y

# CentOS/RHEL
sudo yum install samba-client -y
```

## 2. 기본 사용법

### 2.1 공유 목록 확인 (SMB 열거)

```bash
// : 공유 폴더를 나타내는 접두어
//서버명/공유명

# 익명(NULL) 세션으로 공유 목록 확인 (가장 기본)
smbclient -L //<TARGET_IP> -N

# 사용자 계정으로 공유 목록 확인
smbclient -L //<TARGET_IP> -U <USERNAME>%<PASSWORD>

# 도메인 계정으로 공유 목록 확인
smbclient -L //<TARGET_IP> -U <DOMAIN>/<USERNAME>%<PASSWORD>

# 다른 포트 사용 (기본 445가 아닌 경우)
smbclient -L //<TARGET_IP> -p 139 -N
```

### 2.2 공유 접속하기

```bash
# 익명(NULL) 세션으로 공유 접근
smbclient //<TARGET_IP>/<SHARE_NAME> -N

# 사용자 계정으로 공유 접근
smbclient //<TARGET_IP>/<SHARE_NAME> -U <USERNAME>%<PASSWORD>

# 도메인 계정으로 공유 접근
smbclient //<TARGET_IP>/<SHARE_NAME> -U <DOMAIN>/<USERNAME>%<PASSWORD>

# 특정 SMB 버전 강제 지정 (취약점 테스트 시 유용)
smbclient //<TARGET_IP>/<SHARE_NAME> -U <USERNAME>%<PASSWORD> --option="client min protocol=SMB2"
smbclient //<TARGET_IP>/<SHARE_NAME> -U <USERNAME>%<PASSWORD> --option="client max protocol=SMB3"
```

## 3. SMB 내부 명령어 (공유 접속 후)

```bash
# 파일 목록 보기
ls

# 디렉토리 변경
cd <디렉토리명>

# 현재 디렉토리 확인
pwd

# 파일 다운로드
get <파일명> [로컬_파일명]

# 여러 파일 다운로드
mget <파일패턴>  # 예: mget *.txt

# 파일 업로드
put <로컬_파일명> [원격_파일명]

# 여러 파일 업로드
mput <파일패턴>  # 예: mput *.php

# 디렉토리 생성
mkdir <디렉토리명>

# 디렉토리 삭제
rmdir <디렉토리명>

# 파일 삭제
rm <파일명>

# 파일 이름 변경
rename <현재파일명> <새파일명>

# 로컬 쉘 실행
!<명령어>  # 예: !ls -la

# 도움말 보기
help

# 종료
exit
quit
```

## 4. 고급 기능

### 4.1 한 줄 명령 실행

```bash
# 파일 목록 확인 후 종료
smbclient //<TARGET_IP>/<SHARE_NAME> -N -c "ls"

# 특정 파일 다운로드 후 종료
smbclient //<TARGET_IP>/<SHARE_NAME> -U <USER>%<PASS> -c "get secret.txt"

# 특정 파일 업로드 후 종료
smbclient //<TARGET_IP>/<SHARE_NAME> -U <USER>%<PASS> -c "put local.txt remote.txt"

# 여러 명령 연속 실행
smbclient //<TARGET_IP>/<SHARE_NAME> -U <USER>%<PASS> -c "cd folder; ls; get file.txt; exit"
```

### 4.2 재귀적 디렉토리 다운로드

```bash
# smbclient는 기본적으로 재귀 다운로드를 지원하지 않아 직접 스크립트 작성 필요
# 대안: 모든 파일 탐색 후 필요한 것만 다운로드

# 재귀 다운로드 대체 방법 - smbget 사용
smbget -R smb://<TARGET_IP>/<SHARE_NAME>/ -U <USER>%<PASS>

# 재귀적 파일 나열
function recurse {
    echo $1;
    smbclient //<TARGET_IP>/<SHARE_NAME> -c "cd $1; ls" -U <USER>%<PASS> | grep "^  " | awk '{print $1}' | while read f; do
        if [[ $f != "." && $f != ".." ]]; then
            recurse "$1/$f"
        fi
    done
}
recurse "/"
```

## 5. 인증 관련 옵션

```bash
# NT 해시로 인증 (Pass-the-Hash)
smbclient //<TARGET_IP>/<SHARE_NAME> -U <USERNAME> --pw-nt-hash <NT_HASH>

# Kerberos 인증
smbclient //<TARGET_IP>/<SHARE_NAME> -k

# 특정 워크그룹 지정
smbclient //<TARGET_IP>/<SHARE_NAME> -U <USER>%<PASS> -W <WORKGROUP>

# 자동 비밀번호 응답 방지 (대화식 입력)
smbclient //<TARGET_IP>/<SHARE_NAME> -U <USERNAME>

# 세션 암호화 강제 사용
smbclient //<TARGET_IP>/<SHARE_NAME> -e -U <USERNAME>%<PASSWORD>
```

## 6. 주요 옵션 상세 설명

```bash
# 자주 사용하는 기본 옵션
-L <호스트>       # 서버의 공유 목록 표시 (필수값: 호스트/IP)
-N               # Null 세션 사용 (비밀번호 없음)
-U <사용자명>     # 연결할 사용자 이름 지정 (형식: [도메인/]사용자명)
-p <포트>        # 기본값 445가 아닌 다른 SMB 포트 지정
-c <명령어>       # 단일/다중 명령어 실행 후 종료
-d <레벨>        # 디버그 레벨 설정 (0-10, 숫자 높을수록 상세)
-e               # 전송 데이터 암호화 사용
-k               # Kerberos 인증 사용 (AD 환경)
-m <SMB모드>     # 사용할 SMB 프로토콜 버전 지정
-n <NetBIOS이름> # NetBIOS 이름 직접 지정 (기본값: 호스트명)
-W <워크그룹>     # 워크그룹/도메인 이름 지정
-P               # 플레인 텍스트 인증 허용
-I <IP주소>      # 호스트의 IP 주소 직접 지정
-A <인증파일>     # 인증 정보가 있는 파일 사용
-s <설정파일>     # smb.conf 파일 지정
-t <타임아웃>     # 타임아웃 초 설정

# 보안 관련 고급 옵션
--pw-nt-hash     # NT 해시로 비밀번호 제공 (Pass-the-Hash)
--no-pass        # 비밀번호 없음 (Null 세션과 유사)
--use-ccache     # 기존 Kerberos 티켓 사용
--signing=off    # SMB 서명 비활성화
--signing=on     # SMB 서명 활성화
--signing=required # SMB 서명 필수화
--option="client min protocol=<프로토콜>" # 최소 프로토콜 버전 (NT1, SMB2, SMB3)
--option="client max protocol=<프로토콜>" # 최대 프로토콜 버전 (NT1, SMB2, SMB3)

# 성능 및 동작 관련 옵션
--socket-options=<옵션>  # TCP 소켓 옵션 설정
--option="client timeout=<초>" # 클라이언트 타임아웃 설정
--log-level=<레벨>       # 로그 레벨 설정 (0-10)
--send-buffer=<바이트>   # 송신 버퍼 크기
--max-protocol=<프로토콜> # 최대 프로토콜 버전 지정
--quiet                 # 출력 최소화
```

## 7. 옵션 사용 예시 및 조합

```bash
# 기본 인증 및 탐색 옵션들
smbclient -L //<TARGET_IP> -N  # 익명 세션으로 공유 목록 확인
smbclient -L //<TARGET_IP> -U <USER>%<PASS>  # 사용자 인증으로 공유 목록 확인
smbclient //<TARGET_IP>/<SHARE> -p 445 -U <USER>%<PASS> -c "get important.docx"  # 특정 파일 다운로드

# 보안 및 인증 관련 옵션
smbclient //<TARGET_IP>/<SHARE> -k  # Kerberos 인증
smbclient //<TARGET_IP>/<SHARE> -U <USER>%<PASS> -e  # 암호화 사용
smbclient //<TARGET_IP>/<SHARE> -U <USER> --pw-nt-hash <HASH>  # Pass-the-Hash

# 문제해결 및 호환성 옵션
smbclient //<TARGET_IP>/<SHARE> -U <USER>%<PASS> -d 3  # 디버깅 레벨 3
smbclient //<TARGET_IP>/<SHARE> --option="client min protocol=NT1"  # SMB1 사용 강제화
smbclient //<TARGET_IP>/<SHARE> -U <USER>%<PASS> --option="client timeout=30"  # 타임아웃 증가

# 인증 파일 사용 (인증파일 형식: username=<USER>\npassword=<PASS>)
echo -e "username=user\npassword=pass123" > auth.txt
smbclient //<TARGET_IP>/<SHARE> -A auth.txt

# 여러 옵션 조합
smbclient //<TARGET_IP>/<SHARE> -U <USER>%<PASS> -e -p 445 -c "ls" --option="client min protocol=SMB2"
```

## 8. SMB 문제해결

```bash
# 디버그 모드로 실행
smbclient //<TARGET_IP>/<SHARE_NAME> -U <USER>%<PASS> -d 3

# SMB 버전 호환성 문제 해결
smbclient //<TARGET_IP>/<SHARE_NAME> -U <USER>%<PASS> --option="client min protocol=NT1"
smbclient //<TARGET_IP>/<SHARE_NAME> -U <USER>%<PASS> --option="client max protocol=SMB3"

# 연결 타임아웃 증가
smbclient //<TARGET_IP>/<SHARE_NAME> -U <USER>%<PASS> --option="client timeout=30"

# 오류 수준 변경
smbclient //<TARGET_IP>/<SHARE_NAME> -U <USER>%<PASS> --log-level=3

# NetBIOS 이름 지정
smbclient //<TARGET_IP>/<SHARE_NAME> -U <USER>%<PASS> -n <NETBIOS_NAME>
```

## 9. SMB 스캔 및 열거

```bash
# SMB 포트 스캔
nmap -Pn -p 139,445 <TARGET_IP> # SMB 포트 오픈 여부

# SMB 서비스 스캔
nmap -Pn -p 445 --script smb-os-discovery <TARGET_IP> # OS, 도메인, NetBIOS 등
nmap -Pn -p 445 --script smb-enum-shares <TARGET_IP> # 공유 목록
nmap -Pn -p 445 --script smb-enum-users <TARGET_IP> # 사용자 목록
nmap -Pn -p 445 --script smb-protocols <TARGET_IP> # 지원 프로토콜
nmap -Pn -p 445 --script smb-vuln-ms17-010 <TARGET_IP> # 취약점(MS17-010 등)

# NetBIOS 스캔
nbtscan <TARGET_IP> # NetBIOS 이름, 워크그룹, MAC 등
nmblookup -A <TARGET_IP> # NetBIOS 이름 확인

# 종합 SMB 열거 도구
enum4linux -a <TARGET_IP> # 사용자, 그룹, 공유, 정책 등 종합 정보
```

## 10. 다른 SMB 도구와 연계

```bash
# SMBMap으로 공유 권한 확인
smbmap -H <TARGET_IP> -u <USER> -p <PASS>

# CrackMapExec으로 인증 시도
crackmapexec smb <TARGET_IP> -u <USER> -p <PASS> --shares

# impacket-smbclient (python 구현)
impacket-smbclient <DOMAIN>/<USER>:<PASS>@<TARGET_IP>
```

## 11. 공격 시나리오 예시

### 11.1 익명 접근 확인 및 정보 수집

```bash
smbclient -L //<TARGET_IP> -N
# 접근 가능한 공유 발견 시
smbclient //<TARGET_IP>/<SHARE> -N -c "ls"
```

### 11.2 발견한 자격 증명으로 접근

```bash
smbclient //<TARGET_IP>/C$ -U Administrator%Password123
# 성공 시 중요 파일 확인
smbclient //<TARGET_IP>/C$ -U Administrator%Password123 -c "cd Windows\\Temp & ls"
```

### 11.3 Pass-the-Hash 공격

```bash
# 관리자 NT 해시 획득 후
smbclient //<TARGET_IP>/C$ -U Administrator --pw-nt-hash 31d6cfe0d16ae931b73c59d7e0c089c0
```
