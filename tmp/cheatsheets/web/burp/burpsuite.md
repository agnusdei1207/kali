# Burp Suite Pro 기본 사용

- Burp Suite — 웹 트래픽 프록시부터 Repeater·Intruder·Decoder까지 통합한 웹 점검 플랫폼. Proxy에서 요청을 가로채고, 도구 간 전송으로 분석·자동화를 이어간다.
- 웹앱 수동 점검의 허브로 쓸 때, 파라미터 조작·인가 테스트·브루트포스를 진행할 때, 인코딩·해시 변환을 빠르게 다룰 때.
- Kali는 burpsuite 명령(java 기반, 기본 설치). Windows는 workspace\web\burp\installers\burpsuite_windows-x64_v2026.10.1.exe 설치 후 실행, 최초 실행에서 보유 라이선스 입력.

## 실행

```bash
# Kali
burpsuite
```

```powershell
# Windows 설치 버전
workspace\web\burp\installers\burpsuite_windows-x64_v2026.10.1.exe
# 설치 후 바로가기 실행, 최초 1회 보유 라이선스 입력
```

- 시작 시 Temporary project / 기존 프로젝트 선택 -> 설정 프리셋(Burp defaults) 선택 -> Start Burp.

## Proxy 리스너와 브라우저 연결

- 기본 리스너는 127.0.0.1:8080. Proxy > Proxy settings에서 확인·추가한다.
- 브라우저 프록시를 127.0.0.1:8080으로 설정하거나, Burp 내장 브라우저(Proxy > Open Browser)를 쓴다.
- HTTPS 인증서: 브라우저에서 http://burp 접속 -> CA certificate 다운로드 -> 시스템·브라우저 인증서 저장소에 가져오기.
- Intercept on/off 토글로 가로채기 제어. 수정 후 Forward로 변조 통과, Drop으로 요청 폐기.

## Repeater

- Proxy 히스토리에서 요청 우클릭 -> Send to Repeater (Ctrl+R).
- 파라미터·헤더를 수정하고 Send로 결과를 즉시 확인. 인가 테스트·파라미터 변조의 기본 도구.
- 요청/응답 표기(Raw, Render 등)는 창 상단에서 전환한다.

## Intruder

- 요청 우클릭 -> Send to Intruder -> Positions 탭에서 페이로드 자리 지정(§ 표시).
- Attack 종류: Sniper(자리 하나씩), Battering Ram(모든 자리 동일 페이로드), Pitchfork(자리별 병렬), Cluster bomb(자리별 조합).
- Payloads 탭에서 리스트 지정. 무료 버전은 스로틀이 있어 대량 공격은 Turbo Intruder 등 확장으로 넘긴다.

## Decoder

- 텍스트를 Base64·URL·HTML·HEX로 인코딩/디코딩하고 해시를 계산한다. 우클릭 -> Send to Decoder로 이어 처리.

## 실전 흐름 예시

```text
1. 브라우저 프록시 설정 -> 대상 로그인
2. Proxy 히스토리에서 로그인 요청 -> Send to Repeater
3. Repeater에서 password 파라미터 변조 후 Send로 응답 확인
4. 사용자명 목록 대량 시도는 Intruder (Cluster bomb)
5. 인가 확인은 Autorize 확장으로 재검증
```

## 팁·트러블슈팅

1. HTTPS 인증서 오류가 나면 CA 인증서 임포트부터 확인한다.
2. Kali에서 실행이 안 되면 java 버전과 burpsuite 패키지 상태를 확인한다.
3. Target > Scope를 먼저 지정하면 히스토리 노이즈가 크게 줄어든다.
