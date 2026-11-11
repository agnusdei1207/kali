- Kali에 windows-binaries 패키지를 설치해 PrintSpoofer.exe 같은 Windows 권한 상승 바이너리를 준비하는 명령
- Windows 타깃에 권한 상승 도구를 전송해야 하는데 Kali에 바이너리가 없을 때의 사전 준비 단계
- Kali에서 sudo apt 설치 가능해야 하고, 설치된 경로(/usr/share/windows-resources/binaries/ 등)에서 바이너리를 확인한 뒤 http.server로 서빙한다

sudo apt update && sudo apt install windows-binaries
