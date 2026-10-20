#!/usr/bin/env python3
# 127.0.0.1:18080 (origin-form) -> Squid (absolute-URI) -> http://127.0.0.1:8080
import socket, threading, sys

LISTEN = ("127.0.0.1", 18080)
PROXY  = ("192.168.199.189", 3128)
HOST   = "127.0.0.1"
PORT   = 8080


def handle(c):
    try:
        c.settimeout(30)
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = c.recv(65535)
            if not d:
                return
            buf += d
        head, _, rest = buf.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        method, path, ver = lines[0].split(b" ")

        if not path.startswith(b"http://"):
            path = ("http://%s:%d%s" % (HOST, PORT, path.decode())).encode()
        lines[0] = b" ".join([method, path, ver])

        clen, hdrs = 0, []
        for ln in lines[1:]:
            low = ln.lower()
            if low.startswith(b"connection:") or low.startswith(b"proxy-connection:"):
                continue
            if low.startswith(b"content-length:"):
                clen = int(ln.split(b":", 1)[1].strip() or 0)
            hdrs.append(ln)
        hdrs.append(b"Connection: close")

        s = socket.create_connection(PROXY, timeout=20)
        s.sendall(b"\r\n".join([lines[0]] + hdrs) + b"\r\n\r\n" + rest)

        need = clen - len(rest)
        while need > 0:
            d = c.recv(min(65535, need))
            if not d:
                break
            s.sendall(d)
            need -= len(d)

        while True:
            d = s.recv(65535)
            if not d:
                break
            c.sendall(d)
        s.close()
    except Exception as e:
        sys.stderr.write("relay: %s\n" % e)
    finally:
        c.close()


srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(LISTEN)
srv.listen(128)
print("relay %s:%d -> squid %s:%d -> http://%s:%d" % (*LISTEN, *PROXY, HOST, PORT))
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
