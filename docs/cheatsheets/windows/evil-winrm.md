# evil-winrm 설치 및 실전 사용법

- WinRM(Windows Remote Management) 셸 클라이언트. PowerShell Remoting 포트(5985 HTTP, 5986 HTTPS)로 원격 PowerShell 세션을 열고 파일 업/다운로드까지 제공한다
- 열거에서 5985/5986 포트가 열려 있고 계정 크리덴셜(평문 패스워드 또는 NTLM 해시)을 확보했을 때, 대화형 셸과 파일 전송을 한 번에 얻으려고 쓴다
- 대상에서 WinRM 활성화(도메인 환경·관리용 서버에서 흔함), 유효한 계정 필요. 로컬 관리자 그룹 계정이면 NTLM 해시만으로도 접속(Pass-the-Hash) 가능

## 1. 설치

```bash
# 루비 먼저 설치 (필수)
sudo apt update
sudo apt install ruby

sudo gem install evil-winrm
```

## 2. 옵션 요약

- -i: 타겟 IP (필수)
- -u: 사용자명 (필수)
- -p: 비밀번호 (선택)
- -H: NTLM 해시 (선택)
- upload: 파일 업로드 (셸 내장 명령, 로컬파일명 지정)
- download: 파일 다운로드 (셸 내장 명령, 원격파일명 지정)

## 3. 기본 사용법

```bash
evil-winrm -i <타겟_IP> -u <사용자명> -p <비밀번호>
```

## 4. 해시 인증 (NTLM hash)

```bash
evil-winrm -i <타겟_IP> -u <사용자명> -H <NTLM_hash>
```

## 5. 파일 업로드/다운로드

셸 접속 후 내장 명령으로 수행한다.

- 업로드: `upload <로컬파일명>`
- 다운로드: `download <원격파일명>`

## 6. 명령 실행 예시

```bash
evil-winrm -i 10.10.53.245 -u Administrator -H REDACTED
```

- 관리자 해시로 바로 로그인

## 7. 실전 팁

- 해시 인증 시 `-H` 옵션만 사용, 비밀번호 필요 없음.
- 파일 업/다운은 evil-winrm 쉘 내에서 직접 명령어 입력.
- 관리자 권한 획득 후 `whoami`, `hostname` 등으로 권한 확인.
