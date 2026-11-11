# PowerShell 기본

별칭, 도움말, 경로 이동, 파이프, 검색, 스크립트 실행 정책.

> 관련 문서: [PowerShell 치트시트](./README.md) · [시스템 정보 수집](./powershell_system_reconnaissance.md) · [파일 조작](./powershell_file_operations.md)

## 별칭 / 명령 찾기

```powershell
# 별칭 전체
Get-Alias

# 이름으로 cmdlet 찾기
Get-Command -Name Remove*
```

자주 쓰는 별칭:

```powershell
ls / dir        # Get-ChildItem
cat             # Get-Content
cp              # Copy-Item
mv              # Move-Item
rm              # Remove-Item
cd              # Set-Location
pwd             # Get-Location
echo            # Write-Output
```

## 도움말

```powershell
Get-Help Get-ChildItem
Get-Help New-LocalUser -Examples
```

환경에 따라 명령이 다르면 `Get-Help`로 먼저 확인한다.

## 경로 이동

```powershell
cd C:\temp                  # 해당 폴더로 이동
Set-Location C:\temp        # cd의 정식 명령
cd ..                       # 상위 폴더
cd \                        # 드라이브 루트
cd ~                        # 홈 디렉터리
cd D:                       # 다른 드라이브
Push-Location C:\temp       # 현재 위치 저장하고 이동
Pop-Location                # 저장한 위치로 복귀
Get-Location                # 현재 위치
pwd                         # Get-Location 별칭
Resolve-Path .\a.txt        # 절대경로로 변환
```

## 출력

```powershell
echo "test"
Write-Output "test"
```

## 파이프

```powershell
Get-ChildItem | Sort-Object Length
Get-ChildItem | Where-Object -Property "Extension" -eq ".txt"
```

## 검색

```powershell
Select-String -Path ".\package-lock.json" -Pattern "hat"
Get-Content plum.sqlite | Select-String "Credentials"
Get-ChildItem | Where-Object -Property Length -gt 100
```

## 스크립트 실행

```powershell
# 실행 정책 허용
Set-ExecutionPolicy RemoteSigned

# 스크립트 실행
.\script.ps1

# 실행 정책 우회
powershell -ep bypass -f .\script.ps1
```

## 프로세스 / 서비스 기본

```powershell
Start-Process notepad.exe
Stop-Process -Name notepad
Get-Process
Get-Service
Restart-Service Spooler
```

프로세스·서비스 상세 열거는 [시스템 정보 수집](./powershell_system_reconnaissance.md)과 [권한 상승](./powershell_privilege_escalation.md)을 본다.
