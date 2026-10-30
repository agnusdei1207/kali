# hostname

## 개요

현재 호스트의 이름을 확인하는 명령이다. OSCP 실습에서는 공격자 머신과 대상 머신을 구별할 때 자주 쓴다.

## 주요 명령

```bash
hostname          # 현재 호스트 이름 (단축 이름)
hostname -I       # 인터페이스에 할당된 모든 IP 주소 (공백으로 구분)
cat /etc/hostname # 파일에 기록된 호스트 이름
```

## 실전에서 하는 일

- 공격자 IP와 대상 IP를 구분할 때 현재 컨테이너/호스트 이름을 먼저 확인한다.
- `hostname -I` 결과에서 VPN 인터페이스(tun0)의 주소를 찾으면, 공격이 어떤 세그먼트에 있었는지 알 수 있다.
- VPN 터널 상태를 전체적으로 보려면 `hostname -I`와 `ip addr show tun0`(iproute2.md)을 함께 본다.

## 결과 예시

```text
hostname
kali
hostname -I
10.10.14.5 192.168.1.15
cat /etc/hostname
kali
```

- 첫 번째 IP(10.10.14.5)가 VPN(tun0) 주소인 경우가 많다. 공격자(LHOST)로 쓸 IP를 고르는 기준이 된다.

## 연관 치트시트

- IP 경로 확인: [iproute2.md](./iproute2.md)
- 이름 ↔ IP 매핑: [hosts.md](../dns/hosts.md)

## 참고 / 증적 팁

- 발견한 항목은 노트(`05-progress-tracker.md`)에 항목·증거와 함께 기록한다.
