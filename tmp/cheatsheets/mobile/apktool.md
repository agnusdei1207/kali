# apktool로 APK 디코딩·재빌드

- apktool — APK를 smali와 리소스(레이아웃·AndroidManifest·strings.xml)로 디코딩하고 다시 빌드하는 도구. 리소스 조작, smali 패치, 재서명 후 재설치 흐름의 표준.
- 앱의 문자열·매니페스트·레이아웃을 직접 수정해야 할 때, jadx로 디컴파일 실패한 코드를 smali 수준에서 고쳐 재빌드할 때, 권한·exported 컴포넌트 구조를 확인할 때.
- Java 필요. 기준 버전 3.0.3: Kali는 apt install apktool, jar 단독 실행은 java -jar apktool_3.0.3.jar. Windows는 workspace\mobile\apktool\apktool_3.0.3.jar 경로 예시.

## 기본 명령어 구조

```bash
apktool [command] [options]
# command: d(디코드) / b(빌드) / if(프레임워크 설치)
```

## APK 디코딩

```bash
java -jar apktool_3.0.3.jar d target.apk -o target_src
```

- `d`: decode. smali/ 디렉터리에 바이트코드, res/와 AndroidManifest.xml이 텍스트로 풀린다.
- `-o target_src`: 출력 디렉터리 지정.

```bash
apktool d target.apk -o target_src
apktool d target.apk -f
apktool d target.apk -s -o target_res
```

- `-f`: 출력 디렉터리가 있어도 강제 덮어쓰기.
- `-s`: smali(sources) 제외, 리소스만 디코드.
- `-r`: resources 제외, smali만 디코드.

## smali 수정 후 재빌드

```bash
apktool b target_src -o target_patched.apk
```

- `b`: build. 수정한 smali·리소스를 다시 APK로 패키징한다.
- 재빌드만 한 상태로는 서명이 없어 설치가 거부된다. apksigner로 서명해야 한다.

## 재서명 후 설치

```bash
keytool -genkey -v -keystore test.keystore -alias test -keyalg RSA -keysize 2048 -validity 10000
apksigner sign --ks test.keystore target_patched.apk
adb install -r target_patched.apk
```

## 실전 흐름 예시

```bash
# 1. 디코드
apktool d target.apk -o target_src

# 2. 흔적 확인
grep -n "debuggable" target_src/AndroidManifest.xml
grep -rn "http://" target_src/res/values/strings.xml

# 3. smali에서 분기 수정 위치 찾기
grep -n "if-eqz\|if-nez" target_src/smali/com/target/app/MainActivity.smali

# 4. 재빌드 + 서명 + 설치
apktool b target_src -o target_patched.apk
apksigner sign --ks test.keystore target_patched.apk
adb install -r target_patched.apk
```

## 팁·트러블슈팅

1. 빌드 오류가 나면 메시지의 리소스 id와 매니페스트 수정 지점을 먼저 확인한다.
2. obfuscated 앱은 smali 패키지가 a/b/c로 나오는데, jadx --deobf 결과와 대조하며 수정 위치를 찾는다.
3. 디버깅 가능하게 만들려면 AndroidManifest.xml의 application 태그에 android:debuggable="true"를 넣고 재빌드한다.
4. adb에서 INSTALL_PARSE_FAILED가 나면 서명 누락이 원인인 경우가 대부분이다.
