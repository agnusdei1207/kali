# dnSpy로 .NET 디컴파일·디버깅

- dnSpy( dnSpyEx 유지보수 포크) — .NET 어셈블리(exe/dll)를 C# 소스로 디컴파일하고, 런타임 디버거로 중단점·변수 감시·코드 패치까지 지원하는 GUI 도구.
- .NET으로 만든 프로그램·게임·악성코드 로직을 분석할 때, 라이선스·비밀번호 검사 분기를 바꿔 동작을 확인할 때, 난독화 해제 후 원본 소스를 복원할 때.
- Windows 전용. workspace\windows\tools\dnSpy\dnSpy.exe (64비트) / dnSpy-x86.exe (32비트 어셈블리 디버깅용). 관리자 권한 권장. 원본 dnSpy는 개발 중단, dnSpyEx 포크가 현재 표준.

## 어셈블리 로드와 분석

```text
1. File > Open (또는 exe를 창으로 드래그)
2. 좌측 어셈블리 트리에서 네임스페이스 > 클래스 > 메서드 확장
3. 상단 검색 상자로 클래스·문자열 검색
4. 더블클릭하면 C#으로 디컴파일된 코드가 표시된다
```

- 디컴파일 표시 언어는 우측 상단 드롭다운에서 C# / IL / VB 등으로 전환한다.
- 관심 문자열(비밀번호·키·URL)은 검색 조건에서 문자열 대상으로 찾는다.

## 디버깅

```text
F9: 중단점 설정/해제
F5: 디버그 시작 (디버깅 가능한 exe일 때)
F10: 프로시저 단위 실행 / F11: 한 단계 실행
File > Attach to Process: 이미 실행 중인 .NET 프로세스에 붙기
```

- Locals/Autos 창에서 지역 변수, Watch 창에서 임의 식을 감시한다.
- 중단점 우클릭 > Conditions로 조건부 중단이 가능하다.

## 코드 수정 후 저장

```text
1. 수정할 메서드에서 Ctrl+E (Edit Method (C#))
2. 코드를 고친 뒤 Compile (Ctrl+Shift+B)
3. File > Save Module (Ctrl+Shift+S)로 패치된 어셈블리 저장
```

- Save Module 대화상자에서 경로를 바꾸면 원본을 보존한 채 새 파일로 저장된다.
- 리소스·바이너리 교체는 어셈블리 트리의 Resources 노드에서 우클릭해 수정한다.

## 실전 예시

```text
# 로그인 검사 우회 흐름
1. 문자열 검색으로 "Invalid password" 위치 찾기
2. 해당 검사 메서드에 F9로 중단점
3. 디버그 실행 후 Locals에서 입력값·비교값 확인
4. Ctrl+E로 검사식을 true 반환으로 수정, Compile
5. Save Module로 저장 후 패치본 실행
```

## 팁·트러블슈팅

1. 32비트 타깃은 dnSpy-x86.exe로 열어야 디버깅이 붙는다.
2. 난독화된 어셈블리는 de4dot으로 클린업 후 dnSpy로 여는 흐름이 표준이다.
3. Save Module 실패는 강한 이름(strong-name) 서명 검증이 원인일 수 있다. 서명 옵션을 해제하고 저장한다.
4. exe만 있고 참조 dll이 깨지면 File > Open으로 참조 dll도 같이 로드해준다.
