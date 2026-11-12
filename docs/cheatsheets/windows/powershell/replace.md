# PowerShell 문자열 치환

- PowerShell 문자열 치환 — -replace 연산자는 정규식으로 치환하고, .Replace() 메서드는 문자 그대로(literal) 치환한다. Get-Content로 읽어 치환 후 Set-Content로 되돌리면 파일 내용 교체가 끝난다.
- 설정 파일·스크립트의 경로나 값을 원격에서 바꿔야 할 때, 서비스가 읽는 ini/config의 실행 파일 경로를 조작해 서비스 재시작 시 자신의 파일이 실행되게 만들 때.
- Windows PowerShell 내장 기능으로 별도 모듈이 필요 없다. 파일 쓰기 권한이 있는 계정 필요.

## -replace와 .Replace() 차이

```powershell
"Editor=notepad.exe" -replace 'Editor=.*', 'Editor=C:\Temp\rev.exe'
"Editor=notepad.exe".Replace("notepad", "calc")
"ABC abc" -replace 'abc', 'X'          # 대소문자 무시, 매칭 전부 치환
"ABC abc" -creplace 'abc', 'X'         # 대소문자 구분
"ABC abc".Replace("abc", "X")          # literal, 대소문자 구분
```

- -replace는 정규식 기반이고 기본으로 대소문자를 구분하지 않는다. 패턴의 . * ( ) [ ] 같은 메타문자는 이스케이프가 필요하다.
- .Replace() 메서드는 literal 치환에 대소문자를 구분한다. 경로처럼 메타문자가 섞인 문자열은 .Replace()가 안전하다.
- 대소문자 구분 정규식 치환은 -creplace 연산자를 쓴다.

## 파일 내용 치환

```powershell
(Get-Content C:\xampp\xampp-control.ini) -replace 'Editor=.*', 'Editor=C:\Temp\msf.exe' | Set-Content C:\xampp\xampp-control.ini
```

- (Get-Content)를 괄호로 감싸는 이유: 전체 내용을 배열로 다 읽은 뒤 치환해야 Set-Content가 같은 파일에 안전하게 쓸 수 있기 때문이다.
- Set-Content는 기본 인코딩(Windows PowerShell 5.1에서 ANSI)으로 쓴다. UTF-8이 필요하면 `-Encoding UTF8`을 붙인다.

## 치환 후 확인

```powershell
Select-String -Path C:\xampp\xampp-control.ini -Pattern "Editor"
```

- Select-String으로 치환이 실제 반영됐는지 한 줄로 확인한다. 서비스가 파일을 이미 읽어둔 상태면 재시작 전까지 변경이 반영되지 않는다.

## 실전 예시

```powershell
# 서비스가 읽는 설정의 실행 파일 경로 교체 예(xampp-control 재시작 시 msf.exe 실행 유도)
(Get-Content C:\xampp\xampp-control.ini) -replace 'Editor=.*', 'Editor=C:\Temp\msf.exe' |
  Set-Content C:\xampp\xampp-control.ini
Select-String -Path C:\xampp\xampp-control.ini -Pattern "Editor"

# 여러 파일 일괄 치환
Get-ChildItem C:\inetpub\wwwroot -Filter *.config -Recurse |
  ForEach-Object { (Get-Content $_.FullName) -replace 'old\.local', 'new.local' |
  Set-Content $_.FullName }
```

## 팁·트러블슈팅

1. 치환 문자열 쪽에서는 $가 그룹 참조로 해석된다. $를 문자 그대로 남기려면 $$로 이스케이프하거나 [regex]::Escape()를 활용한다.
2. 파일이 다른 프로세스에 잠겨 있으면 Set-Content가 실패한다. 서비스를 중지하거나 다른 이름으로 쓴 뒤 원본을 교체한다.
3. 대용량 파일은 Get-Content -Raw로 한 덩어리로 읽어 치환하는 편이 줄 단위 배열보다 빠르다.
