## ✅ 1. 워드프레스 플러그인 구조에 대한 사전 지식

워드프레스는 기본적으로 다음과 같은 디렉터리 구조를 갖습니다:

```
/var/www/html/   (혹은 /var/www/wordpress/)
├── wp-admin/
├── wp-content/
│   ├── plugins/
│   │   ├── hello.php       👈 Hello Dolly 플러그인 파일
│   │   └── jsmol2wp/
│   │       └── php/
│   │           └── jsmol.php   👈 LFI가 존재하는 파일
├── wp-includes/
```
