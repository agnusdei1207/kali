# ps

- Get-Content + Select-String(PowerShell) 또는 type + findstr(cmd)로 plum.sqlite 파일에서 "Credentials" 문자열이 들어간 줄을 골라내는 명령
- 발견한 데이터 파일(plum.sqlite)에서 크리덴셜 힌트를 뽑아낼 때 문자열 검색으로 1차 확인할 때
- 대상 파일에 대한 읽기 권한, PowerShell 또는 cmd 셸 필요. 바이너리 파일이라 히트가 있으면 별도 파서로 다시 검증한다

Get-Content plum.sqlite | Select-String "Credentials"

# cmd

type plum.sqlite | findstr /i "Credentials"
