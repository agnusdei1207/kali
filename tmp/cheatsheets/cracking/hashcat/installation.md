# Hashcat 설치

- hashcat 설치·검증 가이드 — apt 설치, 소스 컴파일(git clone + make), 설치 검증(hashcat -I GPU 인식), 주요 디렉토리(/usr/share/hashcat/rules·OpenCL), OpenCL·video 그룹 권한 트러블슈팅
- 크래킹 환경을 처음 세팅할 때, hashcat이 OpenCL 플랫폼을 찾지 못해 실행에 실패할 때
- Linux와 sudo 권한, GPU별 OpenCL 드라이버(nvidia-opencl-dev, mesa-opencl-icd, intel-opencl-icd) — 소스 빌드는 build-essential·git 필요, 설치 후 hashcat -I로 GPU 인식 확인

## 기본 설치

```bash
# APT 패키지 매니저로 설치
sudo apt update
sudo apt install hashcat

# 버전 확인
hashcat --version
```

## 최신 버전 설치

```bash
# 의존성 설치
sudo apt install build-essential git

# 소스에서 컴파일
git clone https://github.com/hashcat/hashcat.git
cd hashcat
make
sudo make install
```

## 설치 검증

```bash
# 설치 확인
which hashcat
hashcat --help

# GPU 인식 확인
hashcat -I
```

## 주요 디렉토리

- 실행파일: `/usr/bin/hashcat`
- 규칙파일: `/usr/share/hashcat/rules/`
- 예제 해시: `/usr/share/hashcat/examples/`
- OpenCL: `/usr/share/hashcat/OpenCL/`

## 트러블슈팅

### OpenCL 오류

```bash
# Intel GPU 드라이버
sudo apt install intel-opencl-icd

# NVIDIA GPU 드라이버
sudo apt install nvidia-opencl-dev

# AMD GPU 드라이버
sudo apt install mesa-opencl-icd
```

### 권한 문제

```bash
# 현재 사용자를 video 그룹에 추가
sudo usermod -a -G video $USER

# 재로그인 후 확인
groups
```
