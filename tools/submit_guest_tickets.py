#!/usr/bin/env python3
"""osTicket guest ticket bulk submission (lab helper)."""
import argparse, re, time
import requests

SUCCESS = 'Support ticket request created'

def csrf_token(html):
    m = re.search(r'name="__CSRFToken__"[^>]*value="([^"]+)"', html)
    if not m:
        m = re.search(r'value="([^"]+)"[^>]*name="__CSRFToken__"', html)
    return m.group(1) if m else None

def topic_id(html):
    m = re.search(r'<select[^>]*name="topicId"(.*?)</select>', html, re.S)
    if m:
        for v in re.findall(r'<option[^>]*value="([^"]+)"', m.group(1)):
            if v:
                return v
    return ''

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('url')
    ap.add_argument('email')
    ap.add_argument('--count', type=int, default=100)
    ap.add_argument('--delay', type=float, default=0.3)
    ap.add_argument('--prefix', default='guest')
    args = ap.parse_args()

    base = args.url if args.url.endswith('/') else args.url + '/'
    ok = fail = 0
    for i in range(1, args.count + 1):
        s = requests.Session()
        s.headers['User-Agent'] = 'lab-ticket-submitter'
        try:
            r = s.get(base + 'open.php', timeout=15)
            token = csrf_token(r.text)
            if not token:
                print(f'[!] #{i}: CSRF token not found (HTTP {r.status_code})')
                fail += 1
                continue
            data = {
                'a': 'open',
                '__CSRFToken__': token,
                'topicId': topic_id(r.text),
                'name': f'{args.prefix}{i}',
                'email': args.email,
                'subject': f'{args.prefix} {i}',
                'message': f'{args.prefix} ticket {i}',
            }
            r = s.post(base + 'open.php', data=data, timeout=15)
            if SUCCESS in r.text:
                ok += 1
                print(f'[+] #{i}: created')
            else:
                fail += 1
                text = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', r.text))
                pos = text.lower().find('error')
                snippet = text[max(0, pos - 40):pos + 140] if pos >= 0 else text[:140]
                print(f'[-] #{i}: {snippet}')
            time.sleep(args.delay)
        except requests.RequestException as e:
            fail += 1
            print(f'[-] #{i}: {e}')
            time.sleep(args.delay)
    print(f'done: {ok} created, {fail} failed')

if __name__ == '__main__':
    main()
