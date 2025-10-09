# Hashcat 주의사항

## 시스템 안정성

### GPU 온도 관리

```bash
# 온도 모니터링
watch -n 1 nvidia-smi

# 온도 제한 설정
hashcat --hwmon-temp-abort=85  # 85도에서 자동 중단
```

### 전력 소비

- **높은 전력 소비**: GPU 풀로드 시 300-500W
- **전원 공급장치 확인**: 충분한 전력 공급 필요
- **UPS 사용 권장**: 갑작스런 정전 대비

### 시스템 리소스

```bash
# 메모리 사용량 확인
free -h

# CPU 온도 확인
sensors

# 디스크 공간 확인 (로그, 체크포인트)
df -h
```

## 성능 관련 주의사항

### VRAM 부족

```bash
# 해시 수 줄이기
split -l 1000 large_hash.txt hash_part_

# 워드리스트 분할
split -l 10000000 large_wordlist.txt wordlist_part_
```

### 메모리 부족 오류

```bash
# 워크로드 조정
-w 2  # 기본값으로 낮춤

# 최적화 비활성화
# -O 옵션 제거
```

### GPU 호환성

```bash
# OpenCL 디바이스 확인
hashcat -I

# 특정 GPU만 사용
hashcat -d 1  # 첫 번째 GPU만
```

## 보안 및 법적 주의사항

### 합법적 사용

- **권한 확인**: 해당 해시에 대한 크래킹 권한 보유
- **테스트 범위**: 침투 테스트 계약 범위 내
- **개인정보**: 타인의 비밀번호 크래킹 금지

### 데이터 보호

```bash
# 임시 파일 안전 삭제
shred -vfz -n 3 temp_wordlist.txt

# 메모리 덤프 방지
echo 3 > /proc/sys/vm/drop_caches
```

### 로그 관리

```bash
# 크래킹 활동 로그 주의
tail -f /var/log/syslog | grep hashcat

# 히스토리 삭제
history -c
```

## 실용적 주의사항

### 워드리스트 관리

```bash
# 중복 제거
sort -u wordlist.txt > wordlist_unique.txt

# 길이별 분류
awk 'length($0) == 8' wordlist.txt > wordlist_8char.txt
```

### 규칙 적용 시 주의

```bash
# 너무 많은 규칙 조합 피하기
# 메모리 폭발적 증가 가능

# 규칙 테스트
echo "password" | hashcat --stdout -r rule.txt | head -10
```

### 세션 관리

```bash
# 정기적 체크포인트 확인
ls -la ~/.hashcat/sessions/

# 오래된 세션 정리
find ~/.hashcat/sessions/ -mtime +30 -delete
```

## 네트워크 보안

### 원격 크래킹 시

```bash
# SSH 터널링 사용
ssh -L 8080:localhost:8080 user@remote-server

# VPN 연결 확인
ip route show
```

### 클라우드 사용 시

- **데이터 암호화**: 업로드 전 암호화
- **세션 종료**: 작업 완료 후 인스턴스 종료
- **비용 모니터링**: GPU 인스턴스 비용 확인

## 일반적인 오류 및 해결

### OpenCL 오류

```bash
# 드라이버 재설치
sudo apt purge nvidia-*
sudo apt install nvidia-driver-470

# 재부팅 필요
sudo reboot
```

### 권한 오류

```bash
# 사용자를 video 그룹에 추가
sudo usermod -a -G video $USER

# 로그아웃 후 재로그인
```

### 메모리 오류

```bash
# 스왑 증가
sudo fallocate -l 8G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

## 성능 기대치 관리

### 현실적 시간 계산

```bash
# 벤치마크로 성능 확인
hashcat -b -m 0

# 예상 시간 계산
# 키스페이스 ÷ 해시레이트 = 예상 시간
```

### 중단 기준 설정

- **시간 제한**: 24시간, 48시간 등
- **진행률 기준**: 50% 이상 진행 시 중단 고려
- **성공률**: 일부만 성공해도 충분한 경우
