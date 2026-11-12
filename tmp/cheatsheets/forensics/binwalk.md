# binwalk로 펌웨어·이미지 시그니처 분석

- binwalk — 파일 안의 시그니처(매직 바이트, 압축 스트림, 파일시스템)를 스캔해 목록화하고 자동 추출하는 도구. 펌웨어 리버싱의 표준 1단계.
- 펌웨어·디스크 이미지에 어떤 포맷이 섞여 있는지 볼 때, squashfs·gzip·tar 같은 압축 파티션을 뜯어낼 때, 파일 뒤에 붙은 숨은 데이터를 확인할 때.
- Kali는 sudo apt install binwalk (기본 설치). Windows는 네이티브 빌드가 불안정해 WSL 권장. 명령 체계는 2.x·3.x(Rust 재작성판) 공통으로 -e 추출을 쓴다.

## 기본 명령어 구조

```bash
binwalk [옵션] <파일>
```

## 시그니처 스캔

```bash
binwalk firmware.bin
binwalk -A firmware.bin            # 실행 코드(OPCODE) 영역 표시
binwalk --dd='.*' firmware.bin     # 발견 시그니처를 전부 파일로 저장
```

- 출력은 오프셋 + 시그니처 설명. 관심 영역의 오프셋을 여기서 확인한다.

## 자동 추출

```bash
binwalk -e firmware.bin
binwalk -Me firmware.bin
```

- `-e`: 발견된 파일·압축을 자동 추출해 _firmware.extracted/ 디렉터리에 저장.
- `-Me`: 추출 결과를 재귀적으로 다시 추출(중첩 압축·중첩 이미지). 루트 파일시스템을 뽑을 때 필수.

## 추출 후 탐색

```bash
cd _firmware.extracted
find . -type d \( -name "etc" -o -name "bin" \)
find . -name "*.conf" -o -name "*passwd*"
grep -rn "admin\|password" --include="*.conf" .
```

- squashfs는 unsquashfs로 풀려 나오는데 실패하면 squashfs 버전·압축 방식(squashfs-tools)을 확인한다.

## 실전 예시

```bash
# 1. 스캔
binwalk firmware.bin

# 2. 재귀 추출
binwalk -Me firmware.bin

# 3. 관심 오프셋을 수동으로 잘라 추출
dd if=firmware.bin of=rootfs.bin bs=1 skip=3145728 count=4194304
unsquashfs rootfs.bin

# 4. 파일시스템에서 크리덴셜 탐색
grep -rn "root:" _firmware.extracted/ | head
```

## 팁·트러블슈팅

1. Windows는 WSL2(우분투)에 apt install binwalk로 쓰는 편이 안정적이다. 네이티브 포트는 의존성 문제가 잦다.
2. 오탐이 많다. 잡힌 시그니처가 실제 데이터인지는 -e 추출 결과의 크기·내용으로 검증한다.
3. 암호화된 펌웨어는 시그니처가 안 잡힌다. binwalk -E(엔트로피 그래프)로 암호 영역 경계를 먼저 본다.
4. -e로도 안 풀리는 압축은 시그니처 오프셋에서 dd로 잘라 gzip/lzma/zstd로 수동 해제한다.
