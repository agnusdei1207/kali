#!/usr/bin/env bash
# ============================================================
# 금융권 모의해킹 패키지 - Kali Linux 일괄 구성 스크립트
#
# 전제: 인터넷이 안 되는 폐쇄망 환경. 이 스크립트는 네트워크에
#       접속하지 않는다. apt 설치는 패키지 안의 deb 파일만 사용하며
#       --no-download 옵션으로 네트워크 접근을 원천 차단한다.
#
# 용도: 이 스크립트가 있는 폴더의 preferred-vulnerability-tools-kali.zip을
#       해제하고, deb 전체를 오프라인 설치한 뒤, 주요 도구 실행 검증까지 한다.
#
# 사용: sudo ./setup-kali.sh            (전체 진행)
#       sudo ./setup-kali.sh --skip-verify   (검증 생략)
# ============================================================
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KALI_ZIP="$SCRIPT_DIR/preferred-vulnerability-tools-kali.zip"
CHEAT_ZIP="$SCRIPT_DIR/cheatsheets-final.zip"
EXTRACT="$SCRIPT_DIR/kali-extract"
SKIP_VERIFY=0
[ "${1:-}" = "--skip-verify" ] && SKIP_VERIFY=1

step() { echo; echo "== $* =="; }

step "0. 준비 확인"
if [ "$(id -u)" -ne 0 ]; then
  echo "오류: root로 실행해야 한다 (sudo ./setup-kali.sh)"
  exit 1
fi
if [ ! -f "$KALI_ZIP" ]; then
  echo "오류: $KALI_ZIP 이 없다. 이 스크립트는 최종 ZIP을 푼 폴더에서 실행한다."
  exit 1
fi
command -v apt-get >/dev/null || { echo "ERROR: apt-get is missing."; exit 1; }
. /etc/os-release
ARCH=$(dpkg --print-architecture)
if [ "${ID:-}" != "kali" ] || [ "$ARCH" != "amd64" ]; then echo "ERROR: Kali amd64 required (found ${ID:-unknown}/$ARCH)."; exit 1; fi
FREE_KB=$(df -Pk /var/lib/dpkg | awk 'NR==2 {print $4}')
if [ "${FREE_KB:-0}" -lt 15728640 ]; then echo "ERROR: at least 15 GiB free space is required."; exit 1; fi
echo "Root: OK; target=${PRETTY_NAME:-Kali Linux}, arch=$ARCH, free=$((FREE_KB / 1048576)) GiB"

step "1. kali ZIP 해제"
if [ ! -f "$EXTRACT/kali/INSTALL.md" ]; then
  mkdir -p "$EXTRACT"
  if command -v unzip >/dev/null 2>&1; then
    unzip -q -o "$KALI_ZIP" -d "$EXTRACT"
  elif command -v 7z >/dev/null 2>&1; then
    7z x -y "$KALI_ZIP" -o"$EXTRACT" >/dev/null
  elif command -v bsdtar >/dev/null 2>&1; then
    bsdtar -xf "$KALI_ZIP" -C "$EXTRACT"
  elif command -v python3 >/dev/null 2>&1; then
    python3 -m zipfile -e "$KALI_ZIP" "$EXTRACT"
  else
    # 최소 설치 Kali에 추출 도구가 없을 때: deb 세트의 unzip을 부트스트랩한다.
    BOOT_DEB="$SCRIPT_DIR/unzip_6.0-31_amd64.deb"
    if [ -f "$BOOT_DEB" ]; then
      echo "추출 도구가 없어 unzip deb로 부트스트랩한다: $BOOT_DEB"
      dpkg -i "$BOOT_DEB" >/dev/null 2>&1 || dpkg --unpack "$BOOT_DEB" >/dev/null 2>&1
      if command -v unzip >/dev/null 2>&1; then
        unzip -q -o "$KALI_ZIP" -d "$EXTRACT"
      else
        echo "오류: unzip 부트스트랩 실패. unzip을 수동 설치한 뒤 재실행한다."
        exit 1
      fi
    else
      echo "오류: unzip/7z/bsdtar/python3가 모두 없고 부트스트랩용 unzip deb도 없다."
      echo "unzip_6.0-31_amd64.deb를 이 스크립트 옆에 두거나 unzip을 설치한 뒤 재실행한다."
      exit 1
    fi
  fi
fi
if [ ! -d "$EXTRACT/kali/debs" ]; then
  echo "오류: 해제 실패 ($EXTRACT/kali/debs 없음)"
  exit 1
fi
echo "해제 위치: $EXTRACT"
echo "deb 개수: $(ls "$EXTRACT/kali/debs"/*.deb 2>/dev/null | wc -l)"

step "2. deb 무결성 검사 (SHA256SUMS)"
# 이 목록은 Windows에서 만들어졌다: BOM·CRLF·백슬래시 경로가 들어 있고
# 키는 kali/ 폴더 기준 상대경로다. 리눅스에서 검사하려면 정규화가 필요하다.
# BOM 제거(\xef\xbb\xbf), CR 제거(\x0d), 백슬래시→슬래시(tr \134), kali/ 접두.
if [ ! -f "$EXTRACT/SHA256SUMS.txt" ]; then
  echo "ERROR: missing SHA256SUMS.txt; refusing installation."
  exit 1
fi
SUMS=$(mktemp)
sed -e '1s/^\xef\xbb\xbf//' -e 's/\x0d$//' "$EXTRACT/SHA256SUMS.txt" \
  | tr '\134' '/' \
  | awk 'BEGIN{OFS="  "}{print $1, "kali/" $2}' > "$SUMS"
if ! (cd "$EXTRACT" && sha256sum -c --quiet "$SUMS"); then
  rm -f "$SUMS"
  echo "ERROR: checksum validation failed; refusing installation."
  exit 1
fi
SUM_COUNT=$(wc -l < "$SUMS")
DEB_COUNT=$(find "$EXTRACT/kali/debs" -maxdepth 1 -type f -name '*.deb' | wc -l)
rm -f "$SUMS"
if [ "$SUM_COUNT" -ne "$((DEB_COUNT + 2))" ]; then
  echo "ERROR: checksum rows ($SUM_COUNT) != expected files ($DEB_COUNT debs + 2 docs)."
  exit 1
fi
echo "Checksum validation: $SUM_COUNT files passed."

step "3. 치트시트 해제"
if [ -f "$CHEAT_ZIP" ] && [ ! -d "$SCRIPT_DIR/cheatsheets" ]; then
  if command -v unzip >/dev/null 2>&1; then
    unzip -q -o "$CHEAT_ZIP" -d "$SCRIPT_DIR"
  else
    python3 -m zipfile -e "$CHEAT_ZIP" "$SCRIPT_DIR"
  fi
  echo "치트시트: $SCRIPT_DIR/cheatsheets"
else
  echo "생략 (zip 없음 또는 이미 해제됨)"
fi

step "4. deb 전체 오프라인 설치 (몇 분 걸린다)"
# --no-download: 네트워크에서 아무것도 받지 않는다. kali-rolling 버전 스큐
# 때문에 --allow-downgrades가 반드시 필요하다.
# 주의: --no-download는 해석에 쓴 경로를 버리고 캐시 디렉터리에서
# 파일명(경로 제외)만으로 deb을 찾는다. 기본 캐시 위치(/var/cache/apt/archives)는
# 비어 있으므로 "Internal Error, Pathname to install is not absolute"로 실패한다.
# 그래서 Dir::Cache::archives를 deb 폴더로 향하게 해 둔다 (실측 확인: tar 업그레이드 RC=0).
export DEBIAN_FRONTEND=noninteractive
DEBS=("$EXTRACT"/kali/debs/*.deb)
echo "설치 대상 deb: ${#DEBS[@]}개"
APT_LOG=$(mktemp)
set +e
apt-get install --allow-downgrades --no-download \
  -o Dir::Cache::archives="$EXTRACT/kali/debs" \
  -y "${DEBS[@]}" >"$APT_LOG" 2>&1
RC=$?
set -e
tail -20 "$APT_LOG"
if [ "$RC" -ne 0 ]; then echo "ERROR: offline apt failed (RC=$RC); log: $APT_LOG"; exit "$RC"; fi
if ! dpkg --configure -a; then echo "ERROR: dpkg configuration failed; log: $APT_LOG"; exit 1; fi
rm -f "$APT_LOG"

if [ "$SKIP_VERIFY" -eq 1 ]; then echo; echo "SETUP_DONE (검증 생략됨)"; exit 0; fi

step "5. 주요 도구 실행 검증"
RESULTS=/tmp/kali-setup-verify.log
: > "$RESULTS"
PASS=0; FAIL=0

# 파일/패키지 존재 확인 (GUI·무거운 도구는 실행 대신 설치 상태로 확인)
check_pkg() {
  if dpkg-query -W -f='${Status}' "$2" 2>/dev/null | grep -q "install ok installed"; then
    echo "PASS $1 (패키지 설치됨)" >> "$RESULTS"; PASS=$((PASS+1))
  else
    echo "FAIL $1 ($2 미설치)" >> "$RESULTS"; FAIL=$((FAIL+1))
  fi
}
# 버전 출력 확인: 첫 인자로 실패하면 -V, version 순으로 재시도.
# 일부 도구는 첫 줄이 빈 줄이라 grep -m1 . 로 실제 배너를 뽑는다.
check() {
  local name="$1"; shift
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "FAIL $name (명령 없음)" >> "$RESULTS"; FAIL=$((FAIL+1)); return
  fi
  local out=""
  for args in "$@"; do
    out=$("$name" $args 2>&1 | grep -m1 . || true)
    if [ -n "$out" ] && ! printf '%s' "$out" | grep -Eiq 'no help topic|illegal option|unknown option|operation not permitted|command not found|not found|cannot execute|(^| )error([: ]|$)'; then break; fi
    out=""
  done
  if [ -n "$out" ]; then
    echo "PASS $name $out" >> "$RESULTS"; PASS=$((PASS+1))
  else
    echo "FAIL $name (no successful version/help output)" >> "$RESULTS"; FAIL=$((FAIL+1))
  fi
}

if [ -f /.dockerenv ] && command -v setcap >/dev/null 2>&1; then setcap -r /usr/lib/nmap/nmap 2>/dev/null || true; fi
check nmap '--version'
check masscan '--version'
check rustscan '--version' '-V' 'version'
check_pkg amass amass
check subfinder '-version' '-V'
check dnsx '-version' '-V'
check httpx '-version' '-V'
check naabu '-version' '-V'
check ffuf '-V' '--version'
check gobuster '--help'
check feroxbuster '--version' '-V'
check nuclei '-version' '-V'
check katana '-version' '-V'
check dalfox 'version' '--version'
check dirsearch '--version'
check whatweb '--version'
check nikto '-Version' '--version'
check wafw00f '-V' '--version'
check wfuzz '--version'
check arjun '--version' '-V'
check sqlmap '--version'
check commix '--version'
check wpscan '--version'
check cewl '--version'
# 이 deb 세트(testssl.sh 3.2.4)의 실행 파일명은 testssl이다.
check testssl '-v' '--version'
check sslscan '--version'
check sslyze '--version'
check ssh-audit '--version'
check hydra '-h'
check john '--list=build-info'
check hashcat '--version' '-V'
check hashid '-v'
check netexec '--version' '-V'
check searchsploit '-h'
check evil-winrm '-V' '--version'
check proxychains4 '--version'
check sshuttle '--version'
check mitmproxy '--version'
check bettercap '-version' '-V' '--version'
check binwalk '--help'
check jadx '--version'
check apktool '--version'
check rizin '-v'
check fls '-V'
check tshark '--version'
check tcpdump '--version'
check socat '-h'
check chisel 'version' '--version'
check ligolo-proxy '--version' '-V'

check_pkg burpsuite burpsuite
check_pkg zaproxy zaproxy
check_pkg metasploit metasploit-framework
check msfvenom '--help'
check_pkg wireshark wireshark
check_pkg ghidra ghidra
check_pkg bloodhound bloodhound
check_pkg neo4j neo4j
check_pkg responder responder
check_pkg impacket impacket-scripts
check_pkg enum4linux enum4linux-ng
check_pkg smbmap smbmap
check_pkg certipy certipy-ad
check_pkg coercer coercer
check_pkg bloodhound-py bloodhound.py
check_pkg sharphound sharphound
check_pkg openvas openvas-scanner
check_pkg gvm gvmd
check_pkg seclists seclists
check_pkg wordlists wordlists
check_pkg mimikatz mimikatz
check_pkg chisel chisel
check_pkg ligolo ligolo-ng
check_pkg tor tor
check_pkg openvpn openvpn
check_pkg mingw mingw-w64-x86-64-dev
check_pkg exploitdb exploitdb

# Python 도구: impacket 스크립트 직접 실행 (이 deb 세트는 impacket- 접두로 설치됨)
IMPCMD=smbclient.py
command -v smbclient.py >/dev/null 2>&1 || IMPCMD=impacket-smbclient
if command -v "$IMPCMD" >/dev/null 2>&1; then
  out=$("$IMPCMD" --help 2>&1 | grep -m1 . || true)
  [ -n "$out" ] && { echo "PASS impacket ($IMPCMD) $out" >> "$RESULTS"; PASS=$((PASS+1)); } \
               || { echo "FAIL impacket" >> "$RESULTS"; FAIL=$((FAIL+1)); }
else
  echo "FAIL impacket (smbclient.py·impacket-smbclient 없음)" >> "$RESULTS"; FAIL=$((FAIL+1))
fi

sort "$RESULTS" -o "$RESULTS"
cat "$RESULTS"
echo
echo "결과: PASS $PASS / FAIL $FAIL"

step "6. 완료 요약"
echo "도구        : apt로 시스템 전역 설치 완료 (PATH에서 바로 실행)"
echo "워드리스트  : /usr/share/seclists, /usr/share/wordlists (rockyou는 gunzip 필요)"
echo "치트시트    : $SCRIPT_DIR/cheatsheets"
echo "참고: 제한 컨테이너에서는 Nmap raw socket 권한 때문에 실행이 실패할 수 있다. 설치 스크립트는 Docker에서만 /usr/lib/nmap/nmap의 setcap을 제거한다."
echo "참고: Burp/ZAP/Wireshark는 GUI라서 데스크톱 세션의 메뉴에서 실행한다"
if [ "$FAIL" -ne 0 ]; then echo "SETUP_FAILED (verification failures: $FAIL)"; exit 1; fi
echo "SETUP_DONE"
