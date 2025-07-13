# netdiscover

- 네트워크 내 활성 호스트 탐지용

## 기본 명령어

netdiscover

## 주요 옵션

- -r <필수>: 스캔할 IP 범위 (예: 192.168.10.0/24)
- -i <필수>: 사용할 인터페이스 (예: eth1)
- -P <선택>: 패시브 모드
- -s <선택>: 패킷 전송 속도 (기본값 1)

## 예시

netdiscover -r 192.168.10.0/24 -i eth1
netdiscover -i eth0

---

# arp-scan

- ARP 패킷으로 네트워크 내 호스트 탐지

## 기본 명령어

arp-scan

## 주요 옵션

- -I <필수>: 사용할 인터페이스 (예: eth1)
- <필수>: 스캔할 IP 범위 (예: 192.168.10.0/24)
- --localnet <선택>: 로컬 네트워크 전체 스캔
- --ignoredups <선택>: 중복 결과 무시

## 예시

arp-scan -I eth1 192.168.10.0/24
arp-scan -I eth0 --localnet
arp-scan -I eth1 10.10.10.0/24 --ignoredups

---

# 실전 팁

- 인터페이스명은 ifconfig/ip a로 확인
- 결과에서 MAC 주소, IP, 벤더 정보 확인
- OSCP 시험에서 네트워크 내 타겟 빠르게 찾을 때 사용
