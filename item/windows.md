1. 디렉터리/파일 탐색

- dir : 현재 폴더 파일/디렉터리 목록
  - 필수: 없음
  - 예시: `dir`
- dir /s /b <파일명> : 하위 폴더 포함 특정 파일 검색
  - 필수: /s, /b, 파일명(확장자 포함)
  - 예시: `dir /s /b flag.txt`
  - 예시: `dir /s /b *.txt`
  - 예시: `dir /s /b *.log`
- findstr <문자열> <파일명> : 파일 내 특정 문자열 검색
  - 필수: 문자열, 파일명(확장자 포함)
  - 예시: `findstr password *.txt`
  - 예시: `findstr /s /i "flag" *.*`
- cd <폴더명> : 폴더 이동
  - 필수: 폴더명
  - 예시: `cd Windows`
- cd .. : 상위 폴더 이동
  - 필수: 없음
  - 예시: `cd ..`
- type <파일명> : 텍스트 파일 내용 출력
  - 필수: 파일명(확장자 포함)
  - 예시: `type flag.txt`

2. 파일/폴더 작업

- copy <원본> <대상> : 파일 복사
  - 필수: 원본파일, 대상파일
  - 예시: `copy flag.txt C:\temp\flag.txt`
- move <원본> <대상> : 파일 이동
  - 필수: 원본파일, 대상파일
  - 예시: `move flag.txt C:\temp\flag.txt`
- del <파일명> : 파일 삭제
  - 필수: 파일명
  - 예시: `del flag.txt`
- mkdir <폴더명> : 폴더 생성
  - 필수: 폴더명
  - 예시: `mkdir loot`
- rmdir <폴더명> : 폴더 삭제
  - 필수: 폴더명
  - 예시: `rmdir loot`

3. 시스템 정보

- systeminfo : 시스템 정보 출력
  - 필수: 없음
  - 예시: `systeminfo`
- hostname : 컴퓨터 이름 표시
  - 필수: 없음
  - 예시: `hostname`
- whoami : 현재 사용자 표시
  - 필수: 없음
  - 예시: `whoami`
- net user : 사용자 계정 목록
  - 필수: 없음
  - 예시: `net user`
- net localgroup : 로컬 그룹 목록
  - 필수: 없음
  - 예시: `net localgroup`

4. 네트워크 관련

- ipconfig : 네트워크 정보
  - 필수: 없음
  - 예시: `ipconfig`
- ping <주소> : 연결 확인
  - 필수: 주소(IP/도메인)
  - 예시: `ping 10.10.107.58`
- netstat -ano : 포트/연결 정보
  - 필수: -ano
  - 예시: `netstat -ano`

5. 프로세스/서비스

- tasklist : 프로세스 목록
  - 필수: 없음
  - 예시: `tasklist`
- taskkill /PID <번호> : 프로세스 종료
  - 필수: /PID, 번호
  - 예시: `taskkill /PID 1234`
- sc query : 서비스 목록
  - 필수: 없음
  - 예시: `sc query`
