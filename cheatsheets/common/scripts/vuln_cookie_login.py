#!/usr/bin/python3
from flask import Flask, request, render_template_string, make_response, redirect, url_for

app = Flask(__name__)

try:
    FLAG = open('./flag.txt', 'r').read()
except Exception:
    FLAG = 'DH{sample_vulnerable_cookie_flag}'

users = {
    'guest': 'guest',
    'admin': FLAG
}

INDEX_HTML = """
<!DOCTYPE html>
<html>
<head><title>Index</title></head>
<body>
    <h2>{{ text }}</h2>
    <a href="/login">Login</a>
</body>
</html>
"""

LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
    <form method="POST">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <button type="submit">Login</button>
    </form>
</body>
</html>
"""

@app.route('/')
def index():
    username = request.cookies.get('username', None)
    if username:
        msg = f'Hello {username}, {"flag is " + FLAG if username == "admin" else "you are not admin"}'
        return render_template_string(INDEX_HTML, text=msg)
    return render_template_string(INDEX_HTML, text="Please login")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template_string(LOGIN_HTML)
    elif request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            pw = users[username]
        except KeyError:
            return '<script>alert("not found user");history.go(-1);</script>'
        if pw == password:
            resp = make_response(redirect(url_for('index')))
            resp.set_cookie('username', username)
            return resp 
        return '<script>alert("wrong password");history.go(-1);</script>'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
