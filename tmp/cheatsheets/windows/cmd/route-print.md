# route print로 라우팅 테이블 확인

- route print와 ipconfig /all로 Windows의 라우팅 테이블과 어댑터·DNS 설정을 확인하는 내장 명령 조합. 정적 경로, 기본 게이트웨이, 멀티홈 설정을 파악하고 route add/delete로 경로를 조작할 수 있다.
- 셸 확보 직후 서버가 어떤 서브넷과 연결되어 있는지, 다른 내부망(피벗 대상)이 있는지 판단할 때. 새 경로 추가 후 통신이 안 될 때 라우팅을 검증할 때.
- Windows cmd 셸이면 충분하다. 내장 명령이라 별도 도구가 필요 없고, route add/delete는 관리자 권한을 요구한다.

## 기본 확인

```cmd
route print
ipconfig /all
```

- route print 출력은 Interface List(어댑터와 인덱스), IPv4 Route Table, IPv6 Route Table 순으로 나온다.
- ipconfig /all은 어댑터별 IP·게이트웨이·DNS를 보여주며, 라우팅 경로가 어떤 인터페이스로 나가는지 대조할 때 쓴다.

## 출력 해석

```text
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      10.10.10.1      10.10.10.5     25   <- 기본 게이트웨이
        10.10.10.0    255.255.255.0      On-link         10.10.10.5    281   <- 직결 서브넷
        10.10.10.255  255.255.255.255    On-link         10.10.10.5    281   <- 브로드캐스트
      192.168.50.0    255.255.255.0    10.10.10.254     10.10.10.5     26   <- 수동 추가 정적 경로
```

- Destination 0.0.0.0/0은 기본 게이트웨이다. Gateway 값이 곧 그 서브넷의 게이트웨이 주소다.
- On-link는 자기 인터페이스가 직접 속한 서브넷을 뜻한다. On-link가 아니고 Gateway가 있으면 별도 서브넷이 존재한다는 신호다.
- On-link가 아닌 정적 경로(192.168.50.0 예시)는 서버가 라우터 역할을 하거나 관리자가 수동으로 추가한 경로다. 내부망 탐색·피벗의 단서가 된다.
- `arp -a`의 게이트웨이 MAC과 ipconfig /all의 게이트웨이 IP를 대조하면 실제 링크 상태까지 확인된다.

## 경로 추가·삭제

```cmd
route add 192.168.50.0 mask 255.255.255.0 10.10.10.254 metric 5
route add 0.0.0.0 mask 0.0.0.0 10.10.10.1
route delete 192.168.50.0
route print -4
```

- `route add <대상> mask <넷마스크> <게이트웨이>`: 특정 대역을 지정 게이트웨이로 보내는 경로를 추가한다. 관리자 권한 필요.
- `route delete <대상>`: 경로 제거. `route print -4`는 IPv4만 출력해 결과를 간결히 본다.

## 실전 예시

```cmd
:: 내부에 어떤 대역이 보이는지 한 번에 확인
route print | findstr /C:"0.0.0.0" /C:"10." /C:"192.168" /C:"172."
:: 어댑터별 IP·게이트웨이·DNS 요약
ipconfig /all | findstr /i /C:"IPv4" /C:"Default Gateway" /C:"DNS Servers"
```

- 라우팅 테이블에 다른 서브넷이 잡혀 있으면 그 대역으로 포트 스캔·공유 열거 대상을 확장한다.

## 팁·트러블슈팅

1. route add 후에도 통신이 안 되면 대상 방화벽 문제일 가능성이 먼저다. ping과 Test-NetConnection으로 구분한다.
2. 네트워크 카드 2개 이상(멀티홈) 서버는 서브넷이 여러 개 찍히므로 피벗 우선 대상이 된다.
3. VPN·가상 스위치 경로가 섞여 보일 수 있으니 ipconfig /all의 어댑터 설명과 짝지어 해석한다.
