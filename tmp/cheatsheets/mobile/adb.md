# adb로 안드로이드 디바이스 제어

- adb(Android Debug Bridge) — PC에서 안드로이드 디바이스·에뮬레이터를 제어하는 CLI. 셸 접근, 앱 설치·제거, 파일 복사, 로그, 포트포워딩을 다룬다.
- 점검 대상 앱을 설치할 때, 앱 데이터·캐시 파일을 끌어올 때, logcat으로 앱 동작·에러를 실시간 추적할 때, 디바이스 내부 포트를 PC로 포워딩할 때.
- 디바이스는 개발자 옵션 + USB 디버깅 활성화 필요. Kali는 apt install adb, Windows는 workspace\mobile\platform-tools\adb.exe 경로 예시.

## 디바이스 확인

```bash
adb devices -l
```

- `device`: 정상 연결. `unauthorized`: 디바이스 화면에서 디버깅 허용을 눌러야 한다. `offline`: 재연결 필요.

## 셸과 앱 조작

```bash
adb shell
adb install -r target.apk          # 재설치 포함 설치
adb shell pm list packages | grep target   # 패키지명 검색
adb shell pm list packages -3      # 서드파티 앱만
adb uninstall com.target.app
```

## 파일 복사

```bash
adb pull /data/data/com.target.app/shared_prefs out_prefs
adb push payload.bin /data/local/tmp/
adb shell ls /data/local/tmp
```

- /data/data는 일반 셸 권한으로 접근이 안 되면 `run-as com.target.app` 또는 root(에뮬레이터·루팅 기기)를 쓴다.

## 로그 추적

```bash
adb logcat                         # 전체 로그 실시간
adb logcat | grep -i com.target.app
adb logcat -s TargetTag            # 특정 태그만
adb logcat -d > logcat_dump.txt    # 지금까지 덤프 후 종료
```

## 포트포워딩·무선 접속

```bash
adb forward tcp:8080 tcp:8080      # 디바이스 8080을 PC 8080으로
adb reverse tcp:9000 tcp:9000      # PC 9000을 디바이스 9000으로
adb tcpip 5555                     # USB 연결 상태에서 Wi-Fi 모드 전환
adb connect 192.168.0.10:5555      # 무선 접속
adb shell dumpsys battery          # 상태 확인 예시
```

## 점검 시점 사용 예시

```bash
# 1. 설치 및 패키지 확인
adb install -r target.apk && adb shell pm list packages | grep target

# 2. 데이터 수집
adb pull /data/data/com.target.app/databases out_db

# 3. 내부 API 확인 (포워딩 후 PC에서 접속)
adb forward tcp:8443 tcp:8443
curl -k https://127.0.0.1:8443/
```

## 팁·트러블슈팅

1. unauthorized가 뜨면 디바이스 화면의 디버깅 허용 팝업을 승인한다.
2. 에뮬레이터는 google_apis 시스템 이미지를 써야 adb root가 가능하다.
3. 무선 adb가 끊기면 adb connect 재시도 후 adb kill-server로 서버를 재시작한다.
