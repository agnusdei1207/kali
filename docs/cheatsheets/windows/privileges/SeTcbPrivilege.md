# SeTcbPrivilege — 실습

- 운영체제의 일부(Act as part of the operating system)처럼 동작하는 최상위 특권으로, 임의 사용자의 토큰을 생성·복제할 수 있어 사실상 권한 제한이 없다
- whoami /priv에서 SeTcb가 보이면 사실상 끝난 상태로, SYSTEM 쉘에서 플래그 수집과 SAM·SYSTEM 레지스트리 백업으로 바로 넘어간다
- 보통 SYSTEM 계정에만 부여되어 일반 서비스·관리자 셸에서 만나기 드물다. 이미 SYSTEM이면 이 특권 활용보다 자격 증명 수집이 다음 일이다

- 뜻: 운영체제의 일부처럼 동작 (Act as part of the operating system)
- 핵심: 가장 강력한 특권 중 하나. 토큰을 직접 만들어낼 수 있어 사실상 제한이 없다

## 1. 특권 상태 확인

```powershell
whoami /priv | findstr /i "SeTcb"
```

보통 SYSTEM 계정에만 있다. 일반 서비스 계정에는 거의 없음

```powershell
whoami
```

## 2. 토큰 확인

```powershell
whoami /priv | findstr /i "SeTcb"
whoami /all | findstr /i "SeTcb"
```

- SeTcb가 있으면 임의 사용자의 토큰을 생성/복제할 수 있다

## 3. 이해 포인트

- 이론상 최강이지만 실전에서 단독으로 만나는 경우는 드물다
- 이미 SYSTEM이면 이 특권은 당연히 있고, 여기서 할 일은 자격 증명 수집/지속성
- SYSTEM 쉘 우선순위: 플래그 → SAM/SYSTEM 백업

### 플래그 수집

```powershell
type C:\Users\Administrator\Desktop\proof.txt
dir C:\Users\*\Desktop\local.txt C:\Users\*\Desktop\proof.txt
```

### SAM/SYSTEM 백업

```powershell
reg save HKLM\SAM C:\temp\SAM
reg save HKLM\SYSTEM C:\temp\SYSTEM
```
