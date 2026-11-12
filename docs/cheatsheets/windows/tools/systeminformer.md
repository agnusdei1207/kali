# SystemInformer(구 Process Hacker) 사용

- SystemInformer — Process Hacker의 후속 오픈소스 시스템 모니터. 프로세스·핸들·네트워크·서비스·토큰을 상세 열거하고, 커널 드라이버로 심층 정보를 제공한다.
- 프로세스별 권한·토큰·핸들을 들여다볼 때, 포트와 프로세스를 실시간 매핑할 때, 서비스 실행 파일 경로·시작 유형을 확인해 권한상승 후보를 찾을 때.
- Windows 전용. 관리자 권한 필수(드라이버 로드 시 더 깊은 정보). workspace\windows\tools\systeminformer\systeminformer.exe 예시. GitHub releases에서 설치형·포터블 제공.

## 실행

```powershell
# 관리자 권한으로 실행
workspace\windows\tools\systeminformer\systeminformer.exe
```

- 첫 실행에 설정 마법사가 나오고, 드라이버(KSystemInformer)를 설치하면 프로세스 숨김 탐지·심층 열거가 활성화된다.
- 일반 권한으로는 다른 사용자·SYSTEM 프로세스의 상세 정보가 제한된다.

## 주요 탭

- Processes: 프로세스 트리 + 실시간 그래프. 우클릭 > Properties에서 토큰·핸들·스레드·모듈 확인.
- Network: 연결마다 로컬·원격 주소와 소유 프로세스가 매핑된다(TCPView 대체).
- Services: 서비스 상태·실행 파일 경로·시작 유형. 서비스 경로 하이재킹 후보 확인용.
- Users: 세션별 사용자 프로세스 확인.
- Tools: 네트워크 도구(traceroute, whois), Explorer, 서비스 생성, 인증서 보기 등 부가 도구 모음.

## 핵심 기능 흐름

```text
1. Ctrl+F (Find Handles or DLLs) — 특정 DLL·뮤텍스·파일 핸들을 쓰는 프로세스 검색
2. 프로세스 우클릭 > Properties > Handles 탭 — 파일·레지스트리·디바이스 핸들 열람
3. Network 탭에서 의심 연결 우클릭 > Go to process
4. Properties > Token 탭 — 권한(SeDebugPrivilege 등) 확인
```

## 유용한 시나리오

```text
# 취약 서비스 경로 확인
Services 탭 > 서비스 선택 > Properties > General 탭의 Path

# 프로세스가 연 파일 보기
Ctrl+F > 검색어 입력 > 해당 핸들 우클릭 > Properties

# 트래픽 급증 원인 파악
Network 탭 > 프로세스별 정렬 > 연결 상세
```

## 팁·트러블슈팅

1. 정보가 비어 있으면 관리자 권한으로 재실행한다. 대부분의 빈 화면은 권한 문제다.
2. 드라이버 설치 여부는 Settings > Advanced > KSystemInformer에서 확인·제거할 수 있다.
3. 백신이 드라이버 로드를 경고할 수 있다. 분석 환경 정책에 맞게 선택한다.
4. Process Hacker 구 문서도 메뉴 구조가 거의 같아 대부분 그대로 적용된다.
