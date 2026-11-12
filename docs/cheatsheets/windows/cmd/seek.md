# dir /s /b로 파일 검색

- dir /s /b — Windows 내장 dir 명령 조합. /s는 하위 디렉터리까지 재귀, /b는 헤더·요약 없이 전체 경로만 한 줄씩 출력한다. 문서·설정·키 파일을 빠르게 찾아 목록으로 만든다.
- 셸 확보 후 자격증명·설정·키 자료(KeePass DB, SSH 키, RDP 정보, 자동화 스크립트)가 저장된 파일을 수집할 때. 백업·인스톨러 등 흥미로운 파일 위치를 목록으로 뽑을 때.
- Windows cmd 셸이면 충분하다(내장 명령). 디스크 전체 스캔은 오래 걸리므로 시작 디렉터리를 좁혀 실행한다.

## 기본 구조

```cmd
dir /s /b C:\Users\*.txt
dir /s /b "C:\Users\user\Documents"
```

- `/s`: 지정 경로 아래 전체 재귀. `/b`: 전체 경로만 한 줄씩 출력해 파이프·리다이렉트에 적합하다.
- 시작 경로를 좁힐수록 빠르다. C:\ 전체보다 C:\Users, C:\inetpub, C:\Windows\Temp처럼 가능성 높은 곳부터 본다.

## 흥미로운 파일 패턴

```cmd
dir /s /b C:\Users\*.kdbx
dir /s /b C:\Users\*.rdp
dir /s /b C:\Users\*.pem C:\Users\*.ppk C:\Users\*.pfx C:\Users\*.key
dir /s /b C:\Users\*.ps1 C:\Users\*.bat C:\Users\*.cmd C:\Users\*.vbs
dir /s /b C:\inetpub\web.config
dir /s /b C:\config* C:\credential* C:\secret* C:\backup*
dir /s /b C:\Users\*.txt C:\Users\*.xml C:\Users\*.ini
```

- *.kdbx(KeePass), *.rdp(원격 접속 정보), *.pem/*.ppk/*.pfx/*.key(키 파일), *.ps1/*.bat(자동화 스크립트)가 1차 수집 대상이다.
- dir은 파일명·패턴 검색이고, 파일 내용 기반 검색은 findstr /s가 담당한다. 두 도구를 역할을 나눠 쓴다.

## 검색 결과 후속 처리

```cmd
dir /s /b C:\Users\*.kdbx > C:\Windows\Temp\found.txt
dir /s /b C:\Users\user\Documents | findstr /i "pass config secret"
```

- /b 출력은 그대로 다음 명령의 입력으로 쓸 수 있다. findstr로 2차 필터링하거나 리다이렉트로 저장해 한 번에 전송한다.

## 실전 예시

```cmd
:: 문서·바탕화면·다운로드 우선 훑기
dir /s /b C:\Users\user\Documents C:\Users\user\Desktop C:\Users\user\Downloads

:: SSH 키와 RDP 연결 정보 탐색
dir /s /b C:\Users\user\.ssh
dir /s /b C:\Users\user\Documents\*.rdp

:: 설치 폴더의 설정 파일
dir /s /b C:\xampp\*.ini C:\xampp\*config*
```

## 팁·트러블슈팅

1. File Not Found가 나오면 매칭 파일이 없다는 뜻이 아니라 검색 경로가 잘못된 경우가 많다. 경로 끝 슬래시와 큰따옴표를 확인한다.
2. dir /s /b C:\처럼 최상위부터 돌리면 접근 거부 디렉터리가 많아 오래 걸린다. 시작 경로를 Users·inetpub 등으로 쪼개 실행한다.
3. 숨김·시스템 파일까지 보려면 /a 옵션을 붙인다. dir /s /b /a C:\Users처럼 쓴다.
