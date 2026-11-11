# PowerShell 파일 조작

조회, 생성, 복사, 이동, 삭제, 플래그 파일 탐색, 해시, ACL.

> 관련 문서: [PowerShell 치트시트](./README.md) · [파일 전송](./powershell_file_transfer.md)

## 목록 조회

```powershell
Get-ChildItem
ls
dir

Get-ChildItem -Path C:\Users
```

## 플래그 / 파일 찾기

```powershell
# 내용으로 찾기
Get-ChildItem -Recurse -File -ErrorAction SilentlyContinue | Select-String "FLAG\{"

# 파일명으로 찾기
Get-ChildItem -Path C:\ -Include local.txt, proof.txt -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Recurse -File -Include local.txt,proof.txt -ErrorAction SilentlyContinue

# 이름 패턴으로 찾기
Get-ChildItem -Path C:\Users -Recurse -File -ErrorAction SilentlyContinue |
Where-Object Name -match 'flag|proof|local'

# cmd 내장 findstr
findstr /s /i "flag" C:\*.txt 2>nul

# 각 사용자 바탕화면
Get-ChildItem -Path C:\Users\*\Desktop -File
```

## 생성 / 복사 / 이동 / 삭제

```powershell
# 폴더 생성
New-Item -Path C:\temp\out -ItemType Directory -Force

# 파일 생성 + 내용 넣기
New-Item -Path C:\temp\a.txt -ItemType File -Value "test"

# 복사
Copy-Item -Path .\a.txt -Destination C:\temp\ -Force

# 이동 / 이름 변경
Move-Item -Path C:\temp\a.txt -Destination C:\temp\b.txt
Move-Item -Path .\exploit.exe -Destination C:\Windows\Temp\ -Force

# 이름만 변경
Rename-Item -Path C:\temp\b.txt -NewName c.txt

# 삭제
Remove-Item -Path C:\temp\a.txt -Force

# 여러 파일 한 번에 이동
Get-ChildItem C:\temp | Move-Item -Destination C:\temp\archive\
```

## 해시

```powershell
Get-FileHash -Path .\ship-flag.txt
Get-FileHash -Algorithm MD5 .\payload.exe
certutil -hashfile .\payload.exe SHA256
```

## ACL / 권한

```powershell
# 파일 ACL 상세
Get-Acl .\file.txt | Format-List

# 디렉토리 권한 확인
icacls C:\temp

# 권한 부여 (Full Control)
icacls C:\temp /grant Administrator:F

# 상속 설정 변경
icacls "C:\Program Files\x" /inheritance:e

# 상위 폴더 권한 확인
(Get-Acl C:\Windows\System32).Access | Select-Object IdentityReference, FileSystemRights
```
