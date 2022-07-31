#!/usr/bin/env python3

import socket
import os

def hostname_resolves(hostname):
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.error:
        return False


def check_ping():
    hostname = "overflow.htb"
    response = os.system("ping -c 1 " + hostname)
    if response == 0:
        return True
    else:
        return False

