import re, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

BASE = r"C:\workspace\kali\tmp\cheatsheets"

tools = """active-directory/bloodhound.md active-directory/crackmapexec.md active-directory/impacket.md
common/crypto/crypto_count.md linux/cli/scp.md recon/curl/proxies-and-tls.md
shells/reverse-shell/linux_bash_reverse_shell.md shells/reverse-shell/linux_perl_reverse_shell.md
shells/reverse-shell/linux_python_reverse_shell.md web/file-inclusion.md web/file-upload.md web/idor.md
web/ssrf.md web/wordpress.md web/xss.md windows/powershell/invoke_webrequest.md
windows/privileges/PrintSpoofer.md windows/privileges/SeChangeNotifyPrivilege.md
windows/privileges/SeShutdownPrivilege.md windows/privileges/winPEASany.exe.md
windows/rdp/evil-winrm.md windows/tools.md windows/cmd/schtasks.md""".split()

readmes = """cracking/README.md linux/README.md metasploit/README.md methodology/post-exploitation/README.md
methodology/post-exploitation/creds.md methodology/post-exploitation/shell.md
methodology/privilege-escalation/README.md methodology/privilege-escalation/linux.md
methodology/privilege-escalation/windows.md methodology/web-attacks/README.md pivoting/README.md
recon/README.md services/README.md shells/README.md windows/powershell/README.md""".split()

FORBIDDEN = ["합법적인 대상", "합법적인 보안 테스트", "오직 교육 목적", "법적 주의사항", "합법적 사용", "합법성"]

def check(path, lo, hi):
    with open(path, encoding="utf-8") as f:
        content = f.read()
    lines = content.splitlines()
    n = len(lines)
    problems = []
    if not (lo <= n <= hi):
        problems.append("LINES=%d (need %d-%d)" % (n, lo, hi))
    infence = False
    for i, ln in enumerate(lines, 1):
        s = ln.strip()
        if s.startswith("```"):
            infence = not infence
            continue
        if infence:
            continue
        if "**" in ln:
            problems.append("bold line %d: %s" % (i, ln[:60]))
        if re.match(r"^\s*\|.*\|\s*$", ln):
            problems.append("table line %d: %s" % (i, ln[:60]))
        for bad in FORBIDDEN:
            if bad in ln:
                problems.append("forbidden '%s' line %d" % (bad, i))
    status = "OK " if not problems else "BAD"
    return status, n, problems

fails = 0
print("== tool docs (40-90) ==")
for f in tools:
    st, n, p = check(BASE + "\\" + f.replace("/", "\\"), 40, 90)
    if st != "OK ": fails += 1
    print("%s %3d %s" % (st, n, f))
    for x in p:
        print("   ", x)

print("== readmes (20-45) ==")
for f in readmes:
    st, n, p = check(BASE + "\\" + f.replace("/", "\\"), 20, 45)
    if st != "OK ": fails += 1
    print("%s %3d %s" % (st, n, f))
    for x in p:
        print("   ", x)

st, n, p = check(BASE + r"\methodology\foothold\default-creds.md", 40, 60)
if st != "OK ": fails += 1
print("== default-creds (40-60): %s %d lines ==" % (st.strip(), n))
for x in p:
    print("   ", x)

print("TOTAL FAILS:", fails)
