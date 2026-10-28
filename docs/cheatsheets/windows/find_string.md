# ps

Get-Content plum.sqlite | Select-String "Credentials"

# cmd

type plum.sqlite | findstr /i "Credentials"
