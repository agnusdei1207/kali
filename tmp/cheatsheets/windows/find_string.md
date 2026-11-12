# findstr로 파일 내 문자열 검색

- findstr — Windows 내장 텍스트 검색 도구. /s로 하위 디렉터리까지 재귀 검색하고 /i로 대소문자를 무시, /m으로 매칭 파일명만 출력한다. grep의 Windows판이며 파이프로 다른 명령 출력도 필터링한다.
- 셸 확보 후 웹루트·설정·문서 파일에서 password, config, connectionstring 같은 키워드가 들어간 파일을 찾을 때. 명령 출력에서 필요한 줄만 걸러낼 때.
- Windows cmd 셸이면 충분하다(내장 명령). 파일 내용 검색이므로 파일명 기반 검색(dir /s /b)과 역할을 구분해 쓴다.

## 기본 재귀 검색

```cmd
findstr /s /i /m "password" *.txt *.xml *.ini *.config
findstr /s /i /m "password passwd pwd" C:\inetpub\wwwroot\*.*
```

- `/s`: 하위 디렉터리까지 재귀. `/i`: 대소문자 구분 해제. `/m`: 내용 대신 매칭 파일명만 출력해 노이즈를 줄인다.
- 검색 대상 경로에 와일드카드를 붙이면 해당 트리 전체를 훑는다. 출력이 많으면 /m을 붙여 파일명만 본다.

## 흥미로운 키워드 집합

```cmd
findstr /s /i /m "password passwd pwd" C:\Users\user\Documents\*.*
findstr /s /i /m "connectionstring datasource server=" C:\inetpub\wwwroot\*.config
findstr /s /i /m "apikey secret token" C:\inetpub\wwwroot\*.*
findstr /i "unattend autologon" C:\Windows\Panther\unattend.xml
```

- web.config 같은 웹 설정의 connectionstring, 설정 XML의 password 필드가 1차 표적이다.
- 키워드를 공백으로 나열하면 OR 검색이 된다. 정규식 패턴은 `/r "pass.*:"`처럼 쓴다.

## 파이프와 옵션 조합

```cmd
route print | findstr /i "10. 192.168. 172."
ipconfig /all | findstr /i "dns gateway ipv4"
type C:\Users\user\Documents\notes.txt | findstr /i "pass"
findstr /s /i /n "password" C:\inetpub\wwwroot\*.*
```

- 다른 명령 출력에서 필요한 줄만 추출하는 용도로 가장 많이 쓴다. `/n`: 줄 번호를 붙여 위치를 알려준다.
- `/c:`는 공백 포함 문구를 하나의 검색어로 묶는다. `findstr /c:"Default Gateway"`처럼 쓴다.

## 실전 예시

```cmd
:: 결과를 파일로 저장해 한 번에 전송
findstr /s /i /m "password" C:\inetpub\wwwroot\*.* > C:\Windows\Temp\hits.txt

:: dir 결과에 2차 필터(확장자·키워드)
dir /s /b C:\Users\user\Documents | findstr /i ".kdbx .pem .ppk"

:: 내용 검색 + 줄 번호
findstr /s /n /i "password" C:\xampp\*.ini C:\xampp\*.php
```

## 팁·트러블슈팅

1. findstr는 기본으로 . * 같은 정규식 메타문자를 해석한다. 마침표를 문자 그대로 찾으려면 /l을 붙이거나 .을 [.]로 바꾼다.
2. 바이너리 파일에서도 매칭이 나와 노이즈가 생길 수 있다. 확장자를 명시해 검색 대상을 좁히는 편이 낫다.
3. 접근 거부 디렉터리는 자동으로 건너뛰지만 전체 검색은 느리다. 시작 경로를 Users·inetpub 등으로 좁혀 실행한다.
