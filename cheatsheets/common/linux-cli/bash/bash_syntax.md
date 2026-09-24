```bash
#!/bin/bash
# -----------------------------------------------------------------
# Bash Scripting Cheat Sheet for Penetration Testing & OSCP Prep
# -----------------------------------------------------------------

## [1] 변수 (Variables)
# 변수 선언 시 '=' 양쪽에 공백을 넣지 않음
MY_VARIABLE="Hello World"
NUMBER=100

# 변수 사용: $ 또는 ${} 구문을 사용
echo "[1] 변수 사용: $MY_VARIABLE"
echo "계산 전 숫자: ${NUMBER}"

# 읽기 전용 변수 (변경 불가)
# readonly IMMUTABLE_VAR="Permanent" 

# [2] 특수 변수 (Special Variables - 인자 및 상태)
# $0: 스크립트 파일 이름
# $1, $2, ...: 첫 번째, 두 번째 명령줄 인자
# $#: 전달된 인자의 총 개수 (매우 중요!)
# $*: 모든 인자를 하나의 문자열로 묶음
# $@: 모든 인자를 개별적인 요소로 묶음 (루프에서 유용)
# $?: 직전 명령어의 종료 상태 코드 (Exit Code. 0=성공)

echo "[2] 스크립트 이름: $0"
echo "인자의 개수: $#"
# 인자가 2개 있다고 가정하면, 첫 번째 인자는 $1

# [3] 조건문: test 명령어 구문 ([] 대괄호)

# 1. 숫자 비교 연산자 (Numerical Comparison)
# -eq (Equal), -ne (Not Equal), -gt (Greater Than), -lt (Less Than)
A=10
B=20

if [ $A -lt $B ]; then
    echo "[3] 조건문: A는 B보다 작다."
fi

# 2. 문자열 비교 연산자 (String Comparison)
STR1="kali"
STR2="linux"

# == 또는 = (Equal), != (Not Equal)
if [ "$STR1" != "$STR2" ]; then
    echo "[3] 문자열: 두 문자열은 같지 않다."
fi

# -z (문자열 길이가 0인지 검사), -n (문자열 길이가 0이 아닌지 검사)
if [ -n "$STR1" ]; then
    echo "[3] 문자열: STR1은 비어있지 않다."
fi

# 3. 파일 관련 연산자 (File Test Operators)
FILE_PATH="/etc/passwd"
# -f (일반 파일), -d (디렉터리), -r (읽기 가능), -w (쓰기 가능), -x (실행 가능)
if [ -f "$FILE_PATH" ]; then
    echo "[3] 파일: /etc/passwd는 일반 파일이다."
fi

# [4] 조건문 확장 (Extended Conditionals)
# [[ ]] 구문은 Bash 고유의 기능으로, 더 유연하고 논리 연산자 사용이 쉬움 (&&, ||)
if [[ $A -lt $B && "$STR1" == "kali" ]]; then
    echo "[4] 확장 조건문: A < B 이고 STR1 == kali 이다."
fi

# [5] 케이스 문 (Case Statement)
# 메뉴 선택 및 옵션 처리 시 유용
OPTION="start"
case "$OPTION" in
    start)
        echo "[5] Case: 서비스를 시작합니다."
        ;;
    stop|quit) # 여러 패턴을 | 로 묶을 수 있음
        echo "[5] Case: 서비스를 종료/중단합니다."
        ;;
    *) # 와일드카드: 위에 해당하지 않는 모든 경우
        echo "[5] Case: 알 수 없는 옵션입니다."
        ;;
esac

# [6] 루프 (Loops)

# 1. For 루프: 인자 목록 반복 (침투 테스트 스크립트에서 스캐닝/브루트포싱 타겟 목록에 유용)
for IP in 192.168.1.1 192.168.1.2 192.168.1.3; do
    echo "[6] For 루프: 스캔 타겟: $IP"
done

# 2. While 루프: 조건이 참인 동안 반복
COUNT=1
while [ $COUNT -le 3 ]; do
    echo "[6] While 루프: 횟수 $COUNT"
    COUNT=$((COUNT + 1)) # 산술 연산 (Arithmetic Expansion)
done

# [7] 함수 (Functions)
# 함수 선언: function 이름 { ... } 또는 이름() { ... }
function scan_port() {
    TARGET_IP=$1 # 함수에 전달된 첫 번째 인자를 내부 변수에 저장
    PORT=$2      # 함수에 전달된 두 번째 인자를 내부 변수에 저장
    echo "[7] 함수 실행: $TARGET_IP의 $PORT 포트 스캔 중..."
    # 실제 nc 또는 nmap 명령이 여기에 들어갈 수 있음
    return 0 # 종료 상태 코드 반환
}

# 함수 호출 (인자 전달)
scan_port "10.10.10.1" 8080

# [8] 명령어 치환 및 파이프 (Command Substitution & Piping)

# 1. 명령어 치환: 명령의 출력을 변수에 저장. $(...) 또는 `...` 사용
TODAY_DATE=$(date +"%Y-%m-%d")
echo "[8] 명령어 치환: 오늘 날짜는 $TODAY_DATE"

# 2. 파이프 (|): 한 명령의 출력을 다른 명령의 입력으로 전달
# /etc/passwd에서 'bash'를 포함하는 줄만 찾기
cat /etc/passwd | grep "bash" | awk -F':' '{print $1}'

# [9] 입/출력 리디렉션 (I/O Redirection)
# >: 파일 덮어쓰기, >>: 파일에 추가하기
# 2>: 표준 오류 (Stderr) 리디렉션
# &>: 표준 출력 및 표준 오류를 모두 리디렉션 (결과와 오류 모두 저장)
nmap -p 80 127.0.0.1 > nmap_result.txt 2> nmap_errors.log
# nmap -p 80 127.0.0.1 &> nmap_all.log
```