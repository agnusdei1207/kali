# 클립보드 복사 (clip)

파일/명령 출력을 클립보드에 바로 넣어 Ctrl+V 로 붙여넣기할 때 사용.

## Windows (PowerShell)

```powershell
# 파일 전체를 클립보드로
Get-Content test.py -Raw | Set-Clipboard

# 한 줄씩/기본
Get-Content test.py | Set-Clipboard

# 명령 출력을 클립보드로
ipconfig | Set-Clipboard

# clip.exe (구형, 한글 깨질 수 있음)
Get-Content test.py -Raw | clip.exe
cat test.py | clip.exe
```

## Windows (cmd)

```cmd
clip.exe < test.py
type test.py | clip.exe
```

## Kali / Linux

```bash
# X11 (xclip)
cat test.py | xclip -selection clipboard
xclip -selection clipboard < test.py

# Wayland (wl-clipboard)
cat test.py | wl-copy
wl-copy < test.py

# 설치
sudo apt install xclip wl-clipboard
```

## macOS

```bash
cat test.py | pbcopy
pbcopy < test.py
```

## WSL (Linux on Windows)에서 Windows 클립보드로

```bash
cat test.py | clip.exe
clip.exe < test.py
```

## 터미널에서 직접 복사

- 마우스로 드래그 선택 후 `Ctrl+Shift+C`
- Windows Terminal: 설정에서 "선택 시 자동으로 클립보드에 복사" 켜두면 드래그만으로 복사
- tmux: copy mode (`Prefix + [` ) 후 선택 → `y` (xclip 연동 필요)

## 주의

- `clip.exe`는 한글/UTF-8에서 깨질 수 있음 → PowerShell의 `Set-Clipboard` 권장
- 큰 파일은 클립보드 크기 제한에 걸릴 수 있음 → 필요한 부분만 잘라서 복사
- SSH 원격 세션에서는 로컬 클립보드로 직접 전송 불가 → 파일 저장 후 scp/rsync 또는 터미널 선택 복사 사용
