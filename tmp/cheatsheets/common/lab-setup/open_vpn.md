# open_vpn (VPN 연결)

- .ovpn 설정 파일로 랩 네트워크에 붙는 OpenVPN 클라이언트 연결 정리다. `openvpn --config <파일> --daemon`으로 백그라운드 실행한다.
- 랩 머신에 접근하기 전 가장 먼저, 그리고 "연결은 됐는데 서비스가 안 보인다"는 문제를 만났을 때 VPN 상태부터 점검할 때 쓴다.
- 발급받은 .ovpn 파일과(필요 시) VPN 자격 증명이 필요하다. 연결 후 `ip addr`로 tun0 IP를 확인하고, VPN을 둘 이상 띄우면 포트·계정 충돌이 나므로 하나만 유지한다. AUTH 오류는 자격 증명 문제다.

## 개요

`open_vpn`은 OSCP 실습에서 가장 흔하게 쓰이는 원격 접속 수단이다. VPN을 연결했는지, 연결 후에만 서비스에 접근할 수 있는지는 OSCP 풀이에서 자주 가로채는 단계다.

## 연결

```bash
# 설정 파일 적용
openvpn --config /vpn/test.ovpn --daemon

# 상태 확인
ps aux | grep openvpn
```

## 종료

```bash
sudo killall openvpn
sudo kill -9 <PID>
sudo pkill -9 openvpn
```

## 오류 확인

- `openvpn`이 바로 실행되지 않으면, 로그를 확인한다:
  ```bash
  sudo tail -f /var/log/openvpn/openvpn.log
  ```
- `AUTH` 오류가 보이면 자격증명(IP/비밀번호)이 틀린 것이다.
- IP 주소가 다른 인터페이스(tun0)로 잡혀 있는지 확인한다(자기 자신의 IP로 `ip addr` 확인).

## 실전 팁

- 연결은 매 시도 새로 하고, 기존 연결은 `killall`로 끊는다.
- 두 VPN이 동시에 떠 있으면 포트/계정 충돌이 발생한다. 하나만 유지한다.
- 이 문서는 랩 세팅(common/lab-setup)을 위한 참고 자료다.

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
