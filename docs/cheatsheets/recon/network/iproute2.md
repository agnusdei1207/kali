# iproute2

## 개요

네트워크 인터페이스와 라우팅 정보를 확인하는 명령이다. OSCP 실습의 기초이며, VPN 연결 후 네트워크 구조를 확인할 때 가장 많이 쓴다.

## 주요 명령

```bash
ip addr show tun0     # 인터페이스별 주소 (가장 많이 쓰는 명령)
ip route              # 라우팅 테이블
ip neigh              # ARP/NDP 캐시
ip link               # 활성 인터페이스 목록
```

## 실전에서 하는 일

- VPN 연결 후 `ip addr show tun0`로 터널 IP를 확인한다.
- `ip route`로 도메인 컨트롤러(DC)까지의 경로를 확인한다(피벗팅 계획 수립에 쓴다).
- `ip neigh`에서 `FAILED`가 뜨면 ARP가 안 되어 있다는 뜻이다(공격 경로 막힘 신호).
- 결과에서 `mtu`, `state`를 확인해 방화벽/NAT 설정을 짐작한다.

## 추가 명령어

```bash
ip route show table all   # 모든 테이블의 라우팅
ip rule show             # 커넥션 트래버설 규칙
ip link set tun0 up     # 인터페이스 활성화
ip link set tun0 down   # 비활성화
```

## 팁

- `ip a`만으로 충분한 정보를 얻을 수 있다. OSCP 시험에서는 매 시도마다 한 번씩 쳐도 충분하다.
- 이후 계획은 `ip route`/`ip neigh` 결과로 수립한다.

## 연관 치트시트

- 호스트명 확인: [hostname.md](./hostname.md)

## 참고 / 증적 팁

- 발견한 항목은 노트(`05-progress-tracker.md`)에 항목·증거와 함께 기록한다.

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
