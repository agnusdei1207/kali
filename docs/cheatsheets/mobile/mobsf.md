# MobSF로 모바일 앱 정적 분석

- MobSF(Mobile Security Framework) — APK·IPA·APPX의 정적 분석(매니페스트, 하드코딩 시크릿, 위험 API, 컴포넌트 노출)과 동적 분석을 웹 UI·REST API로 제공하는 프레임워크.
- APK를 열기 전에 리컨·위험 요소를 한 번에 뽑아낼 때, 매니페스트 권한·exported 컴포넌트·웹뷰 설정 이슈를 목록으로 받을 때, 동적 분석(후킹·트래픽)까지 이어갈 때.
- Windows 소스 실행 전제: git clone 후 setup.bat, venv 활성화. 기본 포트 8000. 동적 분석은 Android 에뮬레이터(AVD) 별도 필요.

## 서버 실행 (Windows 소스 기준)

```powershell
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
cd Mobile-Security-Framework-MobSF
setup.bat
venv\Scripts\activate
python manage.py runserver 0.0.0.0:8000
```

- 브라우저에서 http://127.0.0.1:8000 접속, APK를 드래그해 업로드하면 정적 분석이 시작된다.
- 첫 실행 시 설정과 SQLite DB가 자동 생성되고, 초기 계정(username=mobsf, 비밀번호 REDACTED 처리 권장)은 콘솔 로그에 출력된다.

## REST API로 업로드·분석

```bash
# API 토큰 발급
curl -s -X POST http://127.0.0.1:8000/api/v1/get_token -d "username=mobsf&password=<PASSWORD>"

# APK 업로드 + 정적 분석
curl -s -X POST http://127.0.0.1:8000/api/v1/upload -H "Authorization: <TOKEN>" -F "file=@target.apk"

# PDF 리포트 다운로드
curl -s -X POST http://127.0.0.1:8000/api/v1/download_pdf -H "Authorization: <TOKEN>" -d "hash=<SCAN_HASH>"
```

- upload 응답의 hash 값이 스캔 ID이며, 리포트·상태 조회 API에서 그대로 쓴다.

## 정적 분석에서 확인할 항목

- AndroidManifest: exported activity/service/receiver, allowBackup, debuggable, cleartextTraffic.
- 코드 시크릿: 하드코딩된 API 키, 비밀번호, JWT 시크릿.
- 웹뷰 JS 인터페이스 노출, TLS 검증 우회, 위험 권한 조합, 사용 중인 SDK 버전.

## 동적 분석 (에뮬레이터 필요)

- Android Studio의 AVD(x86_64, API 26~34 권장)를 띄우고 adb로 연결한 뒤 MobSF 동적 분석 탭에서 APK를 올린다.
- Frida 후킹 스크립트, logcat, 트래픽 캡처가 UI에서 제공된다.

## 팁·트러블슈팅

1. runserver가 실패하면 venv 활성화 여부와 setup.bat 재실행부터 확인한다.
2. 동적 분석 탭이 비활성이면 에뮬레이터 감지 실패. adb devices로 디바이스가 보이는지 확인한다.
3. UI 결과와 별개로 시크릿 후보는 소스에서 grep으로 재검증한다.
4. 대형 APK는 분석이 오래 걸리니 upload 후 hash로 진행 상태를 조회하는 게 편하다.
