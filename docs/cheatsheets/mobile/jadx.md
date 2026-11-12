# jadx로 APK 디컴파일

- jadx — APK·DEX·AAR·JAR를 Java 소스로 디컴파일하는 도구. 리소스(XML, AndroidManifest)도 같이 풀어주며, jadx-gui로 코드 탐색·검색이 가능하다.
- APK의 로직·하드코딩된 시크릿·API 엔드포인트를 찾을 때, obfuscated 코드를 읽기 좋게 이름 복원(--deobf)할 때, smali 수준보다 Java 수준 분석이 필요할 때.
- Java(JDK 11 이상) 필요. Windows는 JAVA_HOME 설정 후 workspace\mobile\jadx\bin\jadx.bat, Kali는 apt install jadx 또는 PATH의 jadx 사용. 기준 버전 1.5.6.

## 기본 명령어 구조

```bash
jadx [옵션] <input files> (.apk, .dex, .jar, .class, .smali, .zip, .aar, .aab, .xapk ...)
```

## APK 전체 디컴파일

```bash
# Windows
workspace\mobile\jadx\bin\jadx.bat -d out\target target.apk

# Kali
jadx -d out_target target.apk
```

- `-d out\target`: 출력 디렉터리 지정. sources/ 아래에 Java 소스, resources/ 아래에 리소스가 생긴다.

## GUI로 열기

```bash
workspace\mobile\jadx\bin\jadx-gui.bat target.apk

jadx-gui target.apk
```

- 트리에서 클래스 선택, 검색(Ctrl+Shift+F 전체 검색)으로 문자열·클래스를 찾는다.

## 난독화 해제(deobfuscation)

```bash
jadx --deobf -d out_obf target.apk
jadx --deobf --deobf-min 3 --deobf-max 64 -d out_obf target.apk
```

- `--deobf`: a.b.c 같은 짧은 난독화 이름을 고유한 이름으로 복원한다.
- `--deobf-min`, `--deobf-max`: 복원 대상 이름 최소·최대 길이(기본 3, 64).

## 유용한 옵션

- `-r, --no-res`: 리소스 디코딩 생략(코드만 빠르게 볼 때).
- `-s, --no-src`: 소스 디컴파일 생략(리소스만 추출할 때).
- `-j, --threads-count N`: 처리 스레드 수(기본 CPU 절반). 대형 APK에서 조절.
- `--show-bad-code`: 디컴파일이 깨진 부분도 주석과 함께 표시.
- `-e, --export-gradle`: Android Studio에서 열 수 있는 gradle 프로젝트로 저장.

## 실전 예시

```bash
# 스레드 늘려서 빠르게 전체 디컴파일
jadx -j 8 -d out target.apk

# 시크릿 문자열 탐색
grep -rn "api_key\|secret\|token" out/sources | head -50

# 관심 패키지 추적
find out/sources -type d -name "*login*"
```

## 팁·트러블슈팅

1. jadx-gui에서 Out of memory가 나면 bat 파일의 힙 옵션을 늘리거나 `-r`로 리소스를 제외한다.
2. 빈 메서드·디컴파일 실패가 보이면 `--show-bad-code`로 원인을 확인하고, smali까지 필요하면 apktool과 병행한다.
3. Windows에서 java.exe를 찾지 못하면 JAVA_HOME을 JDK 설치 경로로 설정한다.
4. .apks, .xapk 같은 멀티 APK 형식도 입력으로 그대로 받는다.
