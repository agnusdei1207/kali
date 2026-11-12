# Ghidra로 바이너리 리버싱

- Ghidra — NSA가 공개한 오픈소스 리버스 엔지니어링 프레임워크. 디스어셈블리, C 유사 디컴파일러, 함수 그래프, 스크립트(Java/Python)를 제공한다.
- PE/ELF·DLL·펌웨어의 함수 단위 로직 분석이 필요할 때, 디컴파일 뷰로 빠르게 동작을 파악할 때, headless 모드로 다수 바이너리를 일괄 분석할 때.
- JDK 21 이상 필요. 기준 버전 12.2. Windows는 workspace\forensics\ghidra_12.2\ghidraRun.bat, Kali는 ghidraRun(또는 apt install ghidra) 사용.

## GUI 기본 흐름

```text
ghidraRun 실행
  -> File > New Project (Non-Shared Project)
  -> File > Import File (바이너리 선택)
  -> Import 팝업에서 언어·포맷 확인 후 OK
  -> 프로젝트에서 파일 더블클릭으로 CodeBrowser 열기
  -> "Analyze Now?" 팝업에서 Yes (자동 분석 시작)
```

- 분석이 끝나면 왼쪽 Symbol Tree의 Functions에서 함수를 선택하면 오른쪽 Decompiler 창에 C 유사 코드가 나온다.
- 함수 이름에서 L 키로 rename, 데이터 타입은 T 키로 변경. X 키로 참조(xref) 확인.

## headless 일괄 분석

```bash
# Windows
workspace\forensics\ghidra_12.2\support\analyzeHeadless.bat C:\workspace\forensics\proj proj1 -import C:\samples\target.exe

# Kali
analyzeHeadless /tmp/proj proj1 -import /tmp/target.exe
analyzeHeadless /tmp/proj proj1 -process target.exe -postScript ListFunctions.py
```

- `-import`: 파일을 프로젝트로 가져오고 자동 분석까지 수행.
- `-process`: 기존에 import된 파일을 재사용. `-noanalysis`를 붙이면 분석을 생략.
- `-postScript`: 분석 후 실행할 스크립트 지정. 스크립트 경로는 `-scriptPath`로 추가.

## 스크립트

```bash
analyzeHeadless /tmp/proj proj1 -import /tmp/target.exe \
  -scriptPath /tmp/scripts -postScript ListFunctions.py
```

```python
# /tmp/scripts/ListFunctions.py
for f in currentProgram.getFunctionManager().getFunctions(True):
    print(f.getName(), f.getEntryPoint())
```

- Python(Jython)·Java 스크립트를 GUI의 Script Manager에서도 실행할 수 있다.

## 실전 예시

```text
# GUI에서 문자열 기반 추적
# Search > For Strings... 로 문자열 목록 생성 후 관심 키워드 검색
# 문자열 우클릭 > Show References to Xref 로 사용 지점으로 이동
```

```bash
# 여러 바이너리 일괄 분석 (bash 루프)
for f in /tmp/samples/*; do
  analyzeHeadless /tmp/proj proj1 -import "$f" -postScript ListFunctions.py
done
```

## 팁·트러블슈팅

1. ghidraRun이 바로 죽으면 JDK 버전 문제. JAVA_HOME을 JDK 21로 맞춘다.
2. 대형 바이너리는 자동 분석이 수십 분 걸릴 수 있으니 Analysis 옵션에서 불필요한 분석기를 끈다.
3. headless에서 스크립트를 못 찾으면 -scriptPath 누락이 흔한 원인이다.
4. 패킹된 바이너리는 함수가 거의 안 나온다. 섹션 entropy와 entry point 주변부터 수동 추적한다.
