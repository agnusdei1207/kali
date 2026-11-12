# Forensics 치트시트

- 이 폴더 — 디스크·메모리 이미지와 바이너리를 분석하는 포렌식 도구 문서를 모은다.
- 디스크 이미지에서 파일·아티팩트를 추출해야 할 때(sleuthkit, binwalk, foremost), 메모리 덤프에서 프로세스·커맨드라인·자격증명 흔적을 찾아야 할 때(volatility3), 실행 파일 내부를 볼 때(rizin, ghidra) 사용한다.
- Kali 기본 도구가 대부분 포함되어 있고, 이미지 원본은 읽기 전용으로 두고 복사본으로 작업하는 것이 기본 전제다.

## 폴더 구성

- `rizin.md` — rizin 리버스 엔지니어링(바이너리 분석)
- `volatility3.md` — volatility3 메모리 포렌식
- `ghidra.md` — ghidra 디컴파일·바이너리 분석
- `sleuthkit.md` — sleuthkit 디스크·파일시스템 포렌식
- `binwalk.md` — binwalk 펌웨어·이미지 내장 파일 추출
- `foremost.md` — foremost 파일 카빙

## 이미지 분석 표준 절차

```bash
# 1. 디스크 이미지 파티션·파일시스템 확인 (sleuthkit)
mmls disk.img                          # 파티션 테이블
fls -o 2048 disk.img                   # 파일 목록

# 2. 내장 데이터 추출과 카빙
binwalk disk.img                       # 시그니처 스캔
binwalk -e disk.img                    # 내장 파일 자동 추출
foremost -i disk.img -o carved/        # 파일 카빙

# 3. 메모리 덤프 분석 (volatility3)
volatility3 -f memory.dmp windows.info
volatility3 -f memory.dmp windows.pslist
volatility3 -f memory.dmp windows.cmdline
```

- 디스크 이미지는 sleuthkit(파일시스템 관점)과 binwalk·foremost(시그니처·카빙 관점) 두 방향에서 훑는다.
- 메모리 덤프는 volatility3로 프로세스·커맨드라인·네트워크 정보를 뽑고, 최근 버전은 플러그인 명칭이 windows.* 형태다.

## 바이너리 분석

```bash
rizin -A suspicious.exe                # 자동 분석 후 프롬프트
ghidraRun                              # GUI 디컴파일 뷰
strings -n 8 suspicious.exe            # 1차 분류용 문자열 추출
```

- 문자열·해시 기반 분류는 strings와 md5sum·sha256sum으로 시작하고, 동적 분석은 격리 환경 준비 후에 진행한다.

## 실무 포인트

- 원본 이미지는 읽기 전용으로 두고, 해시를 기록한 복사본에서 작업한다.
- 볼륨 섀도 복사본·LNK·prefetch·레지스트리 하이브 같은 Windows 아티팩트는 sleuthkit으로 이미지에서 직접 추출한다.
- 메모리 덤프에서 계정·자격증명 흔적이 필요하면 volatility3 분석 후 mimikatz 계열 도구로 이어진다.

## 관련 문서

- `windows/` — Windows 아티팩트·권한 관련 문서
- `cracking/` — 추출한 해시·키 파일의 크래킹
