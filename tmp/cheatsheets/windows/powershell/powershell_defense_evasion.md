# PowerShell 흔적 제거 / 파일 숨기기

숨김 속성, 로그 내용 비우기, NTFS ADS 확인.

> 관련 문서: [PowerShell 치트시트](./README.md) · [권한 상승 / 지속성](./powershell_privilege_escalation.md)

## 숨김 속성

```powershell
# 숨김 속성
attrib +h C:\temp\rev.exe

# 숨김 + 시스템 파일 위장
attrib +h +s C:\temp\rev.exe
```

## 로그 / 파일 삭제

```powershell
# 로그 내용 비우기
Clear-Content C:\temp\log.txt

# 파일 삭제
Remove-Item C:\temp\rev.exe, C:\temp\log.txt -Force -ErrorAction SilentlyContinue
```

## NTFS ADS

```powershell
# alternate data stream 목록
Get-Content C:\temp\rev.exe -Stream *
Get-Item C:\temp\rev.exe -Stream *
```
