# Volatility3 설치 및 사용법

## 설치

### 방법 1: apt 패키지 매니저

```bash
sudo apt update
sudo apt install volatility3
```

### 방법 2: pip 설치

```bash
pip3 install volatility3
```

### 방법 3: 소스코드 설치

```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip3 install -r requirements.txt
python3 setup.py install
```

## 기본 사용법

### 실행 명령어

```bash
# apt 설치한 경우
vol3 [옵션] [플러그인]

# pip/소스 설치한 경우
python3 vol.py [옵션] [플러그인]
```

### 기본 옵션

```bash
# 메모리 덤프 파일 지정
-f <파일경로>

# 도움말 확인
-h, --help

# 플러그인 목록 확인
--plugin-dirs <디렉토리>

# 출력 형식 지정 (table, json, csv)
-r <형식>
```

## 주요 플러그인

### 시스템 정보

```bash
# OS 정보 확인
vol3 -f memory.dmp windows.info

# 프로세스 목록
vol3 -f memory.dmp windows.pslist

# 프로세스 트리
vol3 -f memory.dmp windows.pstree

# 네트워크 연결 정보
vol3 -f memory.dmp windows.netstat
```

### 프로세스 분석

```bash
# 특정 프로세스 덤프
vol3 -f memory.dmp windows.dumpfiles --pid <PID>

# 프로세스 메모리 덤프
vol3 -f memory.dmp windows.memmap --pid <PID>

# DLL 목록
vol3 -f memory.dmp windows.dlllist --pid <PID>

# 핸들 정보
vol3 -f memory.dmp windows.handles --pid <PID>
```

### 파일 시스템

```bash
# 파일 스캔
vol3 -f memory.dmp windows.filescan

# MFT 분석
vol3 -f memory.dmp windows.mftscan

# 파일 덤프
vol3 -f memory.dmp windows.dumpfiles --virtaddr <주소>
```

### 레지스트리 분석

```bash
# 레지스트리 하이브 목록
vol3 -f memory.dmp windows.registry.hivelist

# 레지스트리 키 출력
vol3 -f memory.dmp windows.registry.printkey --key <키경로>

# 레지스트리 스캔
vol3 -f memory.dmp windows.registry.hivescan
```

### 네트워크 분석

```bash
# 네트워크 연결
vol3 -f memory.dmp windows.netstat

# 네트워크 스캔
vol3 -f memory.dmp windows.netscan
```

### 악성코드 탐지

```bash
# 숨겨진 프로세스 탐지
vol3 -f memory.dmp windows.psxview

# 코드 인젝션 탐지
vol3 -f memory.dmp windows.malfind

# 드라이버 목록
vol3 -f memory.dmp windows.modules

# 서비스 목록
vol3 -f memory.dmp windows.svcscan
```

## 실전 분석 시나리오

### 1. 초기 정보 수집

```bash
# OS 정보 확인
vol3 -f memory.dmp windows.info

# 실행 중인 프로세스 확인
vol3 -f memory.dmp windows.pslist
```

### 2. 의심스러운 프로세스 찾기

```bash
# 프로세스 트리로 부모-자식 관계 확인
vol3 -f memory.dmp windows.pstree

# 숨겨진 프로세스 탐지
vol3 -f memory.dmp windows.psxview
```

### 3. 네트워크 활동 분석

```bash
# 네트워크 연결 확인
vol3 -f memory.dmp windows.netstat

# 의심스러운 연결 추적
vol3 -f memory.dmp windows.netscan
```

### 4. 파일 분석

```bash
# 메모리에서 파일 스캔
vol3 -f memory.dmp windows.filescan | grep -i ".exe"

# 특정 파일 덤프
vol3 -f memory.dmp windows.dumpfiles --physaddr <주소>
```

### 5. 악성코드 탐지

```bash
# 코드 인젝션 탐지
vol3 -f memory.dmp windows.malfind

# 드라이버 분석
vol3 -f memory.dmp windows.modules
```

## 유용한 필터링 기법

### grep 활용

```bash
# 특정 프로세스만 필터링
vol3 -f memory.dmp windows.pslist | grep notepad

# 특정 확장자 파일만 찾기
vol3 -f memory.dmp windows.filescan | grep -i "\.exe$"
```

### PID 기반 분석

```bash
# 특정 PID의 모든 정보 수집
PID=1234
vol3 -f memory.dmp windows.dlllist --pid $PID
vol3 -f memory.dmp windows.handles --pid $PID
vol3 -f memory.dmp windows.memmap --pid $PID
```

## 출력 형식 변경

### JSON 형식

```bash
vol3 -f memory.dmp -r json windows.pslist > pslist.json
```

### CSV 형식

```bash
vol3 -f memory.dmp -r csv windows.pslist > pslist.csv
```

## 성능 최적화

### 메모리 사용량 줄이기

```bash
# 특정 영역만 스캔
vol3 -f memory.dmp windows.pslist --physical

# 결과 제한
vol3 -f memory.dmp windows.filescan | head -100
```

### 병렬 처리

```bash
# 여러 플러그인 동시 실행 (백그라운드)
vol3 -f memory.dmp windows.pslist > pslist.txt &
vol3 -f memory.dmp windows.netstat > netstat.txt &
wait
```

## 자주 발생하는 오류

### 메모리 부족

```bash
# 스왑 공간 늘리기
sudo swapon --show
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

### 플러그인 찾을 수 없음

```bash
# 플러그인 목록 확인
vol3 --help

# 사용 가능한 플러그인 확인
vol3 -f memory.dmp --list-plugins
```

## 추가 리소스

- 공식 문서: https://volatility3.readthedocs.io/
- GitHub: https://github.com/volatilityfoundation/volatility3
- 샘플 메모리 덤프: https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples
