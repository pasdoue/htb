from colorama import Fore, Style


local_colors = {
    'BLUE' : Fore.__dict__['LIGHTBLUE_EX'],
    'CYAN' : Fore.__dict__['LIGHTCYAN_EX'],
    'GREEN' : Fore.__dict__['LIGHTGREEN_EX'],
    'MAGENTA' : Fore.__dict__['LIGHTMAGENTA_EX'],
    'RED' : Fore.__dict__['LIGHTRED_EX'],
    'YELLOW' : Fore.__dict__['LIGHTYELLOW_EX'],
}

def colorize(string: str, color):
    if not color in Fore.__dict__.keys():
        raise ValueError("Color provided does not exists in colorama lib")
    return local_colors[color] + string + Style.RESET_ALL

def color_files(string: str):
    return colorize(string, 'YELLOW')


begin_error = colorize('[-] ', 'RED')
begin_info = colorize('[-] ', 'BLUE')
begin_success = colorize('[+] ', 'GREEN')
begin_warning = colorize('[!] ', 'YELLOW')