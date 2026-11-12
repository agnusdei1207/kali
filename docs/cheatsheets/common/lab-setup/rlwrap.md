# rlwrap

- 명령줄에 readline 편집(방향키·히스토리·탭 완성)을 덧입히는 래퍼 도구다. `rlwrap nc -lvnp 4444`처럼 리버스 쉘 리스너에 함께 쓴다.
- 공격자 머신에서 nc 리스너로 리버스 쉘을 받기 직전에 붙여 띄우면, 붙은 셸에서 이전 명령 재사용과 히스토리 확인이 된다.
- `apt install rlwrap` 설치가 필요하고 공격자 측에서만 쓴다(리스너를 감싸는 것이지 대상 셸이 아니다). Windows 공격자 머신에서는 PowerShell 자체 히스토리로 대체한다.

## 개요

`rlwrap`(readline wrapper)는 명령줄에 읽기 줄 편집(히스토리, 방향키, 탭 완성)을 덧입히는 도구다. 리버스 쉘을 얻을 때 공격자 측 listener에 함께 쓰면 셸 사용이 훨씬 편해진다.

## 설치

```bash
sudo apt update
sudo apt install rlwrap -y
```

## 사용법

```bash
# 공격자 측 listener (리버스 쉘 대기)
rlwrap nc -lvnp 4444
```

- `rlwrap nc -lvnp <포트>`: 리스너를 띄우며 방향키·히스토리 사용 가능.
- `rlwrap` 없이 `nc`만 쓰면 방향키와 히스토리가 작동하지 않아 셸 조작이 불편하다.

## 실전에서 하는 일

1. 공격자 머신에서 `rlwrap nc -lvnp 4444`로 리스너를 연다.
2. 대상 머신에서 리버스 쉘 payload를 실행해 연결한다.
3. 연결된 셸에서 방향키로 이전 명령을 되살리고, 히스토리를 확인한다.

## 주요 옵션

- `-l, --listen`: listen 모드 (서버처럼 대기)
- `-v, --verbose`: 상세 출력
- `-n, --no-history`: 히스토리 파일 사용 안 함

## 참고

- Windows 공격자 머신에서는 rlwrap 대신 PowerShell 자체 히스토리를 쓴다.

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
