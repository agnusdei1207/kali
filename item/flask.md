```python
# Import the Flask class from the flask module

from flask import Flask

# Create an instance of the Flask class representing the application

app = Flask(**name**)

# Define a route for the root URL ('/')

@app.route('/')
def hello_world(): # This function will be executed when the root URL is accessed # It returns a string containing HTML code for a simple web page
return '<html><head><title>Greeting</title></head><body><h1>Hello, World!</h1></body></html>'

# This checks if the script is being run directly (as the main program)

# and not being imported as a module

if **name** == '**main**': # Run the Flask application # The host='0.0.0.0' allows the server to be accessible from any IP address # The port=8080 specifies the port number on which the server will listen
app.run(host='0.0.0.0', port=8080)

```

```bash
flask run --without-threads --host=0.0.0.0
```
