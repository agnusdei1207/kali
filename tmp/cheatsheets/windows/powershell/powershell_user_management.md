# PowerShell 사용자 / 그룹

로컬 사용자·그룹 열거와 현재 계정 확인.

> 관련 문서: [PowerShell 치트시트](./README.md) · [AD 열거](./powershell_active_directory.md) · [시스템 정보 수집](./powershell_system_reconnaissance.md)

## 로컬 사용자

```powershell
Get-LocalUser
net user administrator
net user /domain        # 도메인 사용자 전체
```

## 로컬 그룹

```powershell
Get-LocalGroup
Get-LocalGroupMember Administrators
net localgroup Administrators
net group "Domain Admins" /domain
```

## 현재 계정

```powershell
whoami
whoami /priv
whoami /groups
whoami /all     # 토큰/그룹/특권 전체
```
