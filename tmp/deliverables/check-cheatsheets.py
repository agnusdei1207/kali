import re, sys, pathlib
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = pathlib.Path(r"C:\workspace\kali\tmp\cheatsheets")
BANNED = [("합법", None), ("교육 목적", None), ("법적", "문"), ("합법성", None)]
bold_re = re.compile(r"\*\*[^*\n]+\*\*")

def strip_inline_code(line):
    return re.sub(r"`[^`]*`", "", line)

issues = []
files = sorted(ROOT.rglob("*.md"))
for f in files:
    rel = f.relative_to(ROOT).as_posix()
    try:
        text = f.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        issues.append(f"{rel}: NOT-UTF8")
        continue
    infence = False
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("```"):
            infence = not infence
            continue
        if infence:
            continue
        clean = strip_inline_code(line)
        if bold_re.search(clean):
            issues.append(f"{rel}:{i}: BOLD {clean.strip()[:60]}")
        if stripped.startswith("|"):
            issues.append(f"{rel}:{i}: TABLE {stripped[:60]}")
        for b, exclude_prev in BANNED:
            idx = 0
            while True:
                idx = clean.find(b, idx)
                if idx < 0:
                    break
                if exclude_prev is None or idx == 0 or clean[idx - 1] != exclude_prev:
                    issues.append(f"{rel}:{i}: PHRASE[{b}] {clean.strip()[:60]}")
                    break
                idx += 1
    if text.startswith("\ufeff"):
        issues.append(f"{rel}: BOM")
    if "\r" in text:
        issues.append(f"{rel}: CRLF")
    n = len(text.splitlines())
    # 폴더 인덱스 README는 파일 목록이 본문 전부라 THIN 대상 아님 (스텁 방지 규칙은 본문 문서용)
    if n < 20 and rel.split("/")[-1] != "README.md":
        issues.append(f"{rel}: THIN({n} lines)")

print(f"files checked: {len(files)}")
if issues:
    print(f"issues: {len(issues)}")
    out = pathlib.Path(r"C:\workspace\kali\tmp\deliverables\cheatsheet-issues.txt")
    out.write_text("\n".join(issues) + "\n", encoding="utf-8")
    byfile = {}
    for x in issues:
        f = x.split(":")[0]
        t = x.split(":")[1].split()[0] if ":" in x else "?"
        byfile.setdefault(f, {}).setdefault(t, 0)
        byfile[f][t] += 1
    for f in sorted(byfile):
        tags = ", ".join(f"{t}x{c}" for t, c in sorted(byfile[f].items()))
        print(f" - {f}: {tags}")
else:
    print("ALL CLEAN")
