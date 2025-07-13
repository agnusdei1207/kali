# 디렉터리/파일 탐색

```bat
# 현재 폴더 파일/디렉터리 목록
dir
# 하위 폴더 포함, 경로만 출력, 특정 파일(flag.txt) 검색
dir /s /b flag.txt
# 하위 폴더 포함, 모든 .txt 파일 경로만 출력
dir /s /b *.txt
# 하위 폴더 포함, 모든 .log 파일 경로만 출력
dir /s /b *.log
# 현재 폴더 내 모든 .txt 파일에서 "password" 포함된 줄 검색
findstr password *.txt
# 하위 폴더 포함, 대소문자 무시, 모든 파일에서 "flag" 포함된 줄 검색
findstr /s /i "flag" *.*
# Windows 폴더로 이동
cd Windows
# 상위 폴더로 이동
cd ..
# flag.txt 파일 내용 출력
type flag.txt
```

# 파일/폴더 작업

```bat
# 파일 복사
copy flag.txt C:\temp\flag.txt
# 파일 이동
move flag.txt C:\temp\flag.txt
# 파일 삭제
del flag.txt
# 폴더 생성
mkdir loot
# 폴더 삭제
rmdir loot
```

# 시스템 정보

```bat
# 시스템 정보 출력
systeminfo
# 컴퓨터 이름 표시
hostname
# 현재 사용자 표시
whoami
# 사용자 계정 목록
net user
# 로컬 그룹 목록
net localgroup
```

# 네트워크 관련

```bat
# 네트워크 정보
ipconfig
# 연결 확인
ping 10.10.107.58
# 포트/연결 정보
netstat -ano
```

# 프로세스/서비스

```bat
# 프로세스 목록
tasklist
# 프로세스 종료
taskkill /PID 1234
# 서비스 목록
sc query
```
