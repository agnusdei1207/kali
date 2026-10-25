# Define a base URL, which is the proxy address minus the proxy port
base_url='http://192.168.112.189'
# Define the proxy URL, which is the base URL plus the proxy port
proxy_url="$base_url:3128"

for port in $(cat /tmp/ports_to_check.txt) ; do \
    # Create a test URL string, which is the base URL plus the test port
    echo "$port executing..."
    test_url="$base_url:$port"
    # If we don't find the string `ERROR` the port may be open
    if ! curl -skL --proxy $proxy_url $test_url | grep ERROR > /dev/null ; then \
        echo "$test_url may be open behind the proxy" ; \
    fi ; \

    echo "$port ended"
done
