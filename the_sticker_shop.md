Burp Collaborator는 \*\*PortSwigger사의 웹 보안 테스트 도구인 Burp Suite (버프 스위트)\*\*의 부가 기능 중 하나입니다. **Blind XSS (Cross-Site Scripting, 교차 사이트 스크립팅)** 같은 **비동기적으로 반응하는 취약점**을 탐지할 때 사용됩니다.

---

### 🔍 Burp Collaborator란?

**Burp Collaborator는 외부 서버로부터의 요청을 감지할 수 있는 인터랙션 서버**입니다.
이 서버는 다음과 같은 외부 요청을 모니터링합니다:

- **DNS (Domain Name System) 요청**
- **HTTP(S) 요청**
- **SMTP (Simple Mail Transfer Protocol, 이메일 전송 프로토콜) 요청**

즉, 애플리케이션에서 어떤 동작으로 인해 Burp Collaborator의 도메인으로 요청이 발생하면, \*\*Burp Suite가 그 요청을 캐치하고 "무언가 실행됐다"\*\*는 걸 알려줍니다.

---

### 📦 Blind XSS 테스트에서 어떻게 사용되나?

1. Burp Suite에서 **Burp Collaborator Client**를 엽니다.
2. 자동으로 생성된 **고유한 Collaborator URL**을 복사합니다. 예: `sa6xlni3han13p5f0zgt35x5twznndb2.oastify.com`
3. XSS Payload에 이 URL을 포함시킵니다:

```html
">
<script src="https://sa6xlni3han13p5f0zgt35x5twznndb2.oastify.com"></script>
```

4. 이 Payload를 타겟 애플리케이션에 삽입합니다.
5. 나중에 애플리케이션이 이 스크립트를 백엔드나 어딘가에서 비동기적으로 렌더링할 경우,
   브라우저나 서버가 해당 `script src=`를 호출하게 되고,
   이때 Burp Collaborator는 **해당 요청을 기록합니다.**

---

### 🔔 요약

| 항목          | 설명                                                                   |
| ------------- | ---------------------------------------------------------------------- |
| **기능**      | 외부 요청 감지용 인터랙션 서버                                         |
| **주요 목적** | Blind XSS, SSRF (Server-Side Request Forgery), 기타 비동기 취약점 탐지 |
| **사용 방식** | Payload에 Collaborator 도메인 포함 → 외부 요청 발생 여부 확인          |
| **결과**      | 요청 발생 시 Burp가 알림 제공                                          |

---
