# PowerShell AD 열거

도메인 사용자·그룹·컴퓨터 조회와 Kerberos 티켓 확인.

> 관련 문서: [PowerShell 치트시트](./README.md) · [사용자 관리](./powershell_user_management.md)

## 사용자

```powershell
# 도메인 사용자 전체
Get-ADUser -Filter * -Properties Name,SamAccountName

# 패스워드 마지막 변경 시점
Get-ADUser dean -Properties * | Select-Object -ExpandProperty PasswordLastSet
```

## 그룹

```powershell
# 도메인 어드민 그룹 멤버
Get-ADGroupMember "Domain Admins"

net group "Domain Admins" /domain
```

## 컴퓨터

```powershell
# 도메인 컴퓨터 목록 + OS
Get-ADComputer -Filter * -Property Name,OperatingSystem
```

## Kerberos

```powershell
klist       # 현재 티켓 확인
```
