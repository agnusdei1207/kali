# enum4linux

## 설치 방법

```bash
# Kali에 기본 설치되어 있음
# 수동 설치 필요한 경우
apt-get update
apt-get install enum4linux

# 의존성 패키지 확인
apt-get install smbclient nbtscan polenum
```

## 주요 옵션

```
-U        사용자 목록 가져오기
-M        시스템 머신 목록 가져오기
-S        공유 목록 가져오기
-P        암호 정책 정보 가져오기
-G        그룹 및 멤버 정보 가져오기
-a        모든 단순 열거 수행 (-U -S -G -P -r -o -n -i)
-o        OS 정보 가져오기
-i        프린터 정보 가져오기
-r        사용자 RID 순환
-n        추가 이름 조회 수행(WINS)
-w        워크그룹/도메인 자세히 나열
-u user   사용할 사용자 이름
-p pass   사용할 비밀번호
```

## 자주 사용하는 명령어

```bash
# 모든 정보 수집 (가장 많이 사용)
enum4linux -a 10.10.10.10

# 사용자 정보만 수집
enum4linux -U 10.10.10.10

# 공유 폴더 정보 수집
enum4linux -S 10.10.10.10

# 특정 사용자/비밀번호로 인증 후 정보 수집
enum4linux -u administrator -p password -a 10.10.10.10

# OS 정보만 수집
enum4linux -o 10.10.10.10

# 워크그룹 정보 상세 수집
enum4linux -w 10.10.10.10
```

## 실전 사용 팁

- 항상 `-a` 옵션으로 먼저 전체 정보 수집
- NULL 세션 가능한지 자동 확인해줌
- 결과에서 "Access Denied" 많이 나오면 `-u`와 `-p` 옵션으로 자격증명 제공
- 도메인 컨트롤러에서 `enum4linux -a -u "guest" -p "" <IP>` 시도
- 공유 목록 발견 후 `smbclient`로 접근
- 사용자 목록은 추후 비밀번호 공격에 활용

## 결과 해석

```
[+] = 성공적으로 정보 수집됨
[-] = 정보 수집 실패
[E] = 오류 발생
```

## 대체 도구

```
smbmap -H <IP>       # 공유 목록 + 권한 확인
crackmapexec smb <IP> --shares  # 더 현대적인 SMB 열거 도구
```
