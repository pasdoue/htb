#!/usr/bin/env python3

import logging
import os
from common_tools import Colors, network


main_folder = os.path.dirname(os.path.realpath(__file__))+os.path.sep

payloads_folder = main_folder+'payloads'+os.path.sep
wordlists_folder = main_folder+'wordlists'+os.path.sep
conf_folder = main_folder+'conf'+os.path.sep
logs_folder = main_folder+'logs'+os.path.sep
external_tools = main_folder+'libs'+os.path.sep



#you can custom those variable manually
####################
ip=''
rsa_key = { 'priv' : payloads_folder+'id_rsa', 'pub' : payloads_folder+'id_rsa.pub' }
final_payload_name = 'ret2libc_payload'
####################



logs_config = {
    "level" : logging.DEBUG,
    "format" : "%(asctime)s - %(filename)s:%(lineno)s - [%(levelname)s] - %(message)s",
    "filepath" : os.path.dirname(os.path.realpath(__file__)) + os.path.sep + 'logs' + os.path.sep + 'app.log'
}

generic_headers = {
    'Content-Type':'application/x-www-form-urlencoded',
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36',
    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Accept-Encoding':'gzip, deflate',
    'Accept-Language':'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7'
}


def check_settings():
    global ip

    manual_actions = ""
    red_flag = False

    if not network.hostname_resolves('overflow.htb'):
        manual_actions += Colors.begin_error+"You have to add entry inside "+Colors.colorize('/etc/hosts', 'YELLOW')+" for FQDN "+Colors.colorize("overflow.htb", 'RED')+"\n"
        red_flag = True
    if not network.hostname_resolves('devbuild-job.overflow.htb'):
        manual_actions += Colors.begin_error+"You have to add entry inside "+Colors.colorize('/etc/hosts', 'YELLOW')+" for FQDN "+Colors.colorize("devbuild-job.overflow.htb", 'RED')+"\n"
        red_flag = True
    if not network.check_ping():
        manual_actions += Colors.begin_error+"It appears you cannot join overflow.htb. "+Colors.colorize('PING KO', 'RED')+", check your network config\n"
        red_flag = True
    if not os.path.isfile(wordlists_folder+"rockyou.txt"):
        manual_actions += Colors.begin_error+"You have to add "+Colors.colorize("rockyou.txt", 'RED')+" wordlist inside : "+Colors.colorize(wordlists_folder, 'YELLOW')+"\n"
        red_flag = True
    if not os.path.isfile(external_tools+"padBuster.pl"):
        manual_actions += Colors.begin_error+"You have to add "+Colors.colorize("padBuster.pl", 'RED')+" lib inside : "+Colors.colorize(external_tools, 'YELLOW')+"\n"
        red_flag = True

    if not ip:
        ip = input("Enter your HTB interface ip address :")

    if red_flag:
        print("Rectify those requirements before launching me")
        print(manual_actions)
        return False
    return True