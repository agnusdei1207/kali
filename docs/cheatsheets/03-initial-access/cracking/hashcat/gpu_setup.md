# Hashcat GPU 설정

## GPU 아키텍처 이해

### NVIDIA GPU

```bash
# GPU 정보 확인
nvidia-smi
lspci | grep -i nvidia

# CUDA 버전 확인
nvcc --version
cat /usr/local/cuda/version.txt
```

### AMD GPU

```bash
# AMD GPU 정보
lspci | grep -i amd
rocm-smi

# OpenCL 지원 확인
clinfo
```

### Intel GPU

```bash
# Intel GPU 정보
lspci | grep -i intel
intel_gpu_top
```

## NVIDIA 설정

### 드라이버 설치

```bash
# 기존 드라이버 제거
sudo apt purge nvidia-*
sudo apt autoremove

# 새 드라이버 설치
sudo apt update
sudo apt install nvidia-driver-470
sudo reboot

# 설치 확인
nvidia-smi
```

### CUDA 설치

```bash
# CUDA 툴킷 설치
sudo apt install nvidia-cuda-toolkit

# 또는 최신 버전 설치
wget https://developer.download.nvidia.com/compute/cuda/12.0.0/local_installers/cuda_12.0.0_525.60.13_linux.run
sudo sh cuda_12.0.0_525.60.13_linux.run
```

### 성능 최적화

```bash
# GPU 파워 모드 설정
sudo nvidia-smi -pm 1

# 최대 성능 모드
sudo nvidia-smi -lgc 0,2100

# 메모리 클럭 설정
sudo nvidia-smi -lmc 0,5000
```

## AMD 설정

### ROCm 설치

```bash
# ROCm 저장소 추가
sudo apt update
sudo apt install wget gnupg
wget -qO - https://repo.radeon.com/rocm/rocm.gpg.key | sudo apt-key add -
echo 'deb [arch=amd64] https://repo.radeon.com/rocm/apt/debian/ ubuntu main' | sudo tee /etc/apt/sources.list.d/rocm.list

# ROCm 설치
sudo apt update
sudo apt install rocm-dkms rocm-dev rocm-libs rocm-utils

# 사용자 그룹 추가
sudo usermod -a -G render,video $USER
```

### OpenCL 설정

```bash
# OpenCL 런타임 설치
sudo apt install mesa-opencl-icd
sudo apt install rocm-opencl-icd

# 설정 확인
clinfo
```

## Intel GPU 설정

### 드라이버 설치

```bash
# Intel GPU 드라이버
sudo apt install intel-opencl-icd
sudo apt install intel-gpu-tools

# 레벨 제로 API
sudo apt install level-zero-dev level-zero
```

## 다중 GPU 설정

### GPU 인식 확인

```bash
# 해시캣에서 GPU 확인
hashcat -I

# 출력 예시:
# * Device #1: NVIDIA GeForce RTX 3080
# * Device #2: NVIDIA GeForce RTX 3090
```

### 특정 GPU 사용

```bash
# 첫 번째 GPU만 사용
hashcat -d 1 -m 0 hash.txt wordlist.txt

# 여러 GPU 동시 사용
hashcat -d 1,2 -m 0 hash.txt wordlist.txt

# 모든 GPU 사용
hashcat -d 1,2,3,4 -m 0 hash.txt wordlist.txt
```

### GPU별 워크로드 분산

```bash
# GPU별 워크로드 조정 (수동)
hashcat -d 1 --session=gpu1 hash1.txt wordlist.txt &
hashcat -d 2 --session=gpu2 hash2.txt wordlist.txt &
```

## 성능 튜닝

### 벤치마크 실행

```bash
# 모든 해시 타입 벤치마크
hashcat -b

# 특정 해시 타입만
hashcat -b -m 0    # MD5
hashcat -b -m 1000 # NTLM
hashcat -b -m 22000 # WPA2
```

### 워크로드 튜닝

```bash
# 워크로드 레벨 조정
-w 1  # 낮음 (시스템 반응성 유지)
-w 2  # 기본값
-w 3  # 높음 (전용 크래킹)
-w 4  # 악몽 (최대 성능, 시스템 불안정 가능)
```

### 커널 튜닝

```bash
# 커널 가속도 수동 설정
--kernel-accel=1024

# 커널 루프 수동 설정
--kernel-loops=1024

# 자동 튜닝
--tune
```

## 메모리 최적화

### VRAM 사용량 관리

```bash
# VRAM 사용량 확인
nvidia-smi

# 큰 해시 파일 분할
split -l 10000 large_hash.txt hash_part_

# 배치 처리
for file in hash_part_*; do
  hashcat -m 0 "$file" wordlist.txt
done
```

### 시스템 메모리 최적화

```bash
# 스왑 설정
sudo fallocate -l 16G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# /etc/fstab에 추가
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

## 온도 및 전력 관리

### 온도 모니터링

```bash
# NVIDIA 온도 확인
watch -n 1 nvidia-smi

# AMD 온도 확인
watch -n 1 rocm-smi

# 온도 임계값 설정
hashcat --hwmon-temp-abort=85
```

### 전력 관리

```bash
# 전력 제한 설정 (NVIDIA)
sudo nvidia-smi -pl 300  # 300W로 제한

# 팬 속도 설정
sudo nvidia-settings -a [gpu:0]/GPUFanControlState=1
sudo nvidia-settings -a [fan:0]/GPUTargetFanSpeed=80
```

## 클라우드 GPU 설정

### AWS EC2 GPU 인스턴스

```bash
# P3/P4 인스턴스 권장
# 인스턴스 시작 후 드라이버 설치
sudo apt update
sudo apt install nvidia-driver-470
sudo reboot

# 해시캣 설치
sudo apt install hashcat
```

### Google Cloud Platform

```bash
# GPU 인스턴스 생성 후
# CUDA 드라이버 설치 스크립트 실행
curl https://raw.githubusercontent.com/GoogleCloudPlatform/compute-gpu-installation/main/linux/install_gpu_driver.py --output install_gpu_driver.py
sudo python3 install_gpu_driver.py
```

### Azure GPU VM

```bash
# NC 시리즈 VM 사용
# 사전 설치된 이미지 사용 권장
```

## 트러블슈팅

### 일반적인 오류

#### OpenCL 오류

```bash
# OpenCL 플랫폼 없음
sudo apt install ocl-icd-opencl-dev opencl-headers

# 권한 오류
sudo usermod -a -G video,render $USER
```

#### CUDA 오류

```bash
# CUDA 드라이버 버전 불일치
nvidia-smi  # 드라이버 버전 확인
nvcc --version  # CUDA 버전 확인

# 재설치 필요시
sudo apt purge nvidia-* cuda-*
sudo apt autoremove
# 드라이버 재설치
```

#### 성능 저하

```bash
# 열 스로틀링 확인
nvidia-smi --query-gpu=temperature.gpu --format=csv

# GPU 사용률 확인
nvidia-smi --query-gpu=utilization.gpu --format=csv
```

### 디버깅 명령어

```bash
# 상세 디버그 정보
hashcat --debug-mode=1 -m 0 hash.txt wordlist.txt

# OpenCL 커널 정보
hashcat --opencl-info

# 벤치마크로 안정성 테스트
hashcat -b --benchmark-all
```

## 최적화 체크리스트

### 하드웨어 확인

- [ ] 최신 GPU 드라이버 설치
- [ ] 충분한 전력 공급 (PSU)
- [ ] 적절한 냉각 시스템
- [ ] 충분한 VRAM

### 소프트웨어 설정

- [ ] OpenCL/CUDA 런타임 설치
- [ ] 사용자 권한 설정 (video 그룹)
- [ ] 스왑 메모리 설정
- [ ] 온도 모니터링 설정

### 성능 최적화

- [ ] 벤치마크로 기준 성능 확인
- [ ] 워크로드 레벨 조정
- [ ] 커널 튜닝 실행
- [ ] 다중 GPU 활용
