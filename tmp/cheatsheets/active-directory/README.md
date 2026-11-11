# Active Directory

AD 환경 점검 내용입니다.

## BloodHound

```bash
bloodhound -dc target -domain target.local -collections All
```

## CrackMapExec

```bash
crackmapexec smb target.local -u user -p password
```

## enum4linux

```bash
enum4linux -a target
```

## impacket

```bash
smbexec.py target.local
psexec.py target.local
```

## Kerbrute

```bash
kerbrute passwordspray -userlist users.txt target.local
```
