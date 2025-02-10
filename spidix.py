import requests
import re
from colorama import Fore, Style, init
import json
from Waf import Waf_Detect
from optparse import OptionParser
import subprocess
import sys
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from rich import print as rich_print
from rich.panel import Panel

# Define constants and utility functions
VERSION = 'v1.4'

class Color:
    BLUE = '\033[94m'
    GREEN = '\033[1;92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    ORANGE = '\033[38;5;208m'
    BOLD = '\033[1m'
    UNBOLD = '\033[22m'
    ITALIC = '\033[3m'
    UNITALIC = '\033[23m'

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.1.2 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.70",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/89.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Mobile Safari/537.36",
]

init(autoreset=True)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_exit_menu():
    clear_screen()

    panel = Panel(r"""
 ______               ______              
|   __ \.--.--.-----.|   __ \.--.--.-----.
|   __ <|  |  |  -__||   __ <|  |  |  -__|
|______/|___  |_____||______/|___  |_____|
        |_____|              |_____|      
    """,
            style="bold green",
            border_style="blue",
            expand=False
    )

    rich_print(panel)
    print(Color.RED + "\n\nSession Off..\n")
    sys.exit(0)

print(Fore.LIGHTBLUE_EX + r"""
                                                                    
                                @@@@@@   @@@@@@@   @@@  @@@@@@@   @@@  @@@  @@@  
                               @@@@@@@   @@@@@@@@  @@@  @@@@@@@@  @@@  @@@  @@@  
                               !@@       @@!  @@@  @@!  @@!  @@@  @@!  @@!  !@@  
                               !@!       !@!  @!@  !@!  !@!  @!@  !@!  !@!  @!!  
                               !!@@!!    @!@@!@!   !!@  @!@  !@!  !!@   !@@!@!   
                                !!@!!!   !!@!!!    !!!  !@!  !!!  !!!    @!!!    
                                    !:!  !!:       !!:  !!:  !!!  !!:   !: :!!   
                                   !:!   :!:       :!:  :!:  !:!  :!:  :!:  !:!  
                               :::::::   :::       :::  :::  :::  :::  :::  :::  
                            ::::::::::   :::       : :  ::::::::  :::  :::  :::  
                            ________________________________________________________   
                                                  
                                 # Security is just an Illusion
                                 # Author : Spidix-sec

            """.center(80) + Fore.WHITE + Style.RESET_ALL)

parser = OptionParser()

parser.add_option('-f', dest='filename', help="specify Filename to scan. Eg: urls.txt etc")
parser.add_option("-u", dest="url", help="scan a single URL. Eg: http://example.com/?id=2")
parser.add_option('-o', dest='output', help="filename to store output. Eg: result.txt")
parser.add_option('-t', dest='threads', help="no of threads to send concurrent requests(Max: 10)")
parser.add_option('-H', dest='headers', help="specify Custom Headers")
parser.add_option('--waf', dest='waf',action='store_true', help="detect web application firewall and then test payloads")
parser.add_option('-w', dest='custom_waf',help='use specific payloads related to W.A.F')
parser.add_option('--pipe',dest="pipe",action="store_true",help="pipe output of a process as an input")
parser.add_option('--payloads', dest='payloads', help="specify path to XSS payloads file. Eg: payloads.txt")

val,args = parser.parse_args()
filename = val.filename
threads = val.threads
output = val.output
url = val.url
waf = val.waf
pipe = val.pipe
custom_waf = val.custom_waf
headers = val.headers
payloads_path = val.payloads

try:
    if headers:
        print(Fore.WHITE + "[+] HEADERS: {}".format(headers))
        headers = {header.split(":")[0]: header.split(":")[1].strip() for header in headers.split(',')}
except AttributeError:
    headers = {header.split(":")[0]: header.split(":")[1].strip() for header in headers.split()}

try:
    threads = int(threads)
except TypeError:
    threads = 1
if threads > 10:
    threads = 7

class Main:

    def __init__(self, url=None, filename=None, output=None, headers=None, payloads_path=None):
        self.filename = filename
        self.url = url
        self.output = output
        self.headers = headers
        self.payloads_path = payloads_path
        self.result = []

    def read(self, filename):
        print(Fore.WHITE + "READING URLS")
        urls = subprocess.check_output(f"cat {filename} | grep '=' | sort -u", shell=True).decode('utf-8')
        if not urls:
            print(Fore.GREEN + f"[+] NO URLS WITH GET PARAMETER FOUND")
        return urls.split()

    def write(self, output, value):
        if not output:
            return None
        subprocess.call(f"echo '{value}' >> {output}", shell=True)

    def replace(self, url, param_name, value):
        return re.sub(f"{param_name}=([^&]+)", f"{param_name}={value}", url)

    def bubble_sort(self, arr):
        a = 0
        keys = []
        for i in arr:
            for j in i:
                keys.append(j)
        while a < len(keys) - 1:
            b = 0
            while b < len(keys) - 1:
                d1 = arr[b]
                d2 = arr[b + 1]
                if len(d1[keys[b]]) < len(d2[keys[b+1]]):
                    d = d1
                    arr[b] = arr[b+1]
                    arr[b+1] = d
                    z = keys[b+1]
                    keys[b+1] = keys[b]
                    keys[b] = z
                b += 1
            a += 1
        return arr

    def parameters(self, url):
        param_names = []
        params = urlparse(url).query
        params = params.split("&")
        if len(params) == 1:
            params = params[0].split("=")
            param_names.append(params[0])
        else:
            for param in params:
                param = param.split("=")
                param_names.append(param[0])
        return param_names

    def parser(self, url, param_name, value):
        final_parameters = {}
        parsed_data = urlparse(url)
        params = parsed_data.query
        protocol = parsed_data.scheme
        hostname = parsed_data.hostname
        path = parsed_data.path
        params = params.split("&")
        if len(params) == 1:
            params = params[0].split("=")
            final_parameters[params[0]] = params[1]
        else:
            for param in params:
                param = param.split("=")
                final_parameters[param[0]] = param[1]
        final_parameters[param_name] = value
        return final_parameters

    def validator(self, arr, param_name, url):
        dic = {param_name: []}
        try:
            for data in arr:
                final_parameters = self.parser(url, param_name, data + "randomstring")
                new_url = urlparse(url).scheme + "://" + urlparse(url).hostname + "/" + urlparse(url).path
                if self.headers:
                    response = requests.get(new_url, params=final_parameters, headers=self.headers, verify=False).text
                else:
                    response = requests.get(new_url, params=final_parameters, verify=False).text
                if data + "randomstring" in response:
                    if not threads or threads == 1:
                        print(Fore.GREEN + f"[+] {data} is reflecting in the response")
                    dic[param_name].append(data)
        except Exception as e:
            print(e)

        return dic

    def fuzzer(self, url):
        data = []
        dangerous_characters = []
        with open(self.payloads_path, 'r') as f:
            dangerous_characters = f.read().splitlines()
        parameters = self.parameters(url)
        if '' in parameters and len(parameters) == 1:
            print(Fore.RED + f"[+] NO GET PARAMETER IDENTIFIED...EXITING")
            exit()
        if not threads or int(threads) == 1:
            print(Fore.YELLOW + f"[+] {len(parameters)} parameters identified")
        for parameter in parameters:
            if not threads or threads == 1:
                print(Fore.WHITE + f"[+] Testing parameter name: {parameter}")
            out = self.validator(dangerous_characters,parameter,url)
            data.append(out)
        if not threads or threads == 1:
            print(Fore.GREEN + "[+] FUZZING HAS BEEN COMPLETED")
        return self.bubble_sort(data)

    def filter_payload(self,arr,firewall):
        payload_list = []
        size = int(len(arr) / 2)
        if not threads or threads == 1:
            print(Fore.WHITE + f"[+] LOADING PAYLOAD FILE {self.payloads_path}")
        dbs = []
        with open(self.payloads_path, 'r') as f:
            dbs = json.load(f)
        new_dbs = []
        if firewall:
            print(Fore.GREEN + f"[+] FILTERING PAYLOADS FOR {firewall.upper()}")
            try:
                for i in range(0,len(dbs)):
                    if dbs[i]['waf'] == firewall:
                        new_dbs.append(dbs[i])
            except Exception as e:
                print(e)
            if not new_dbs:
                print(Fore.RED + "[+] NO PAYLOADS FOUND FOR THIS WAF")
                exit()
        else:
            for i in range(0,len(dbs)):
                if not dbs[i]['waf']:
                    new_dbs.append(dbs[i])
        dbs = new_dbs
        for char in arr:
            for payload in dbs:
                attributes = payload['Attribute']
                if char in attributes:
                    payload['count'] += 1
        def fun(e):
            return e['count']
        dbs.sort(key=fun,reverse=True)
        for payload in dbs:
            if payload['count'] == len(arr) and len(payload['Attribute']) == payload['count'] :
                if not threads or threads == 1:
                    print(Fore.GREEN + f"[+] FOUND SOME PERFECT PAYLOADS FOR THE TARGET")
                payload_list.insert(0,payload['Payload'])
                continue
            if payload['count'] > size:
                payload_list.append(payload['Payload'])
                continue
        return payload_list

    def scanner(self,url):
        print(Fore.WHITE + f"[+] TESTING {url}")
        if waf:
            print(Fore.LIGHTGREEN_EX + "[+] DETECTING WAF")
            firewall = Waf_Detect(url).waf_detect()
            if firewall:
                print(Fore.LIGHTGREEN_EX + f"[+] {firewall.upper()} DETECTED")
            else:
                print(Fore.LIGHTGREEN_EX + f"[+] NO WAF FOUND! GOING WITH THE NORMAL PAYLOADS")
                firewall = None
        elif custom_waf:
            firewall = custom_waf
        else:
            firewall = None
        out = self.fuzzer(url)
        for data in out:
            for key in data:
                payload_list = self.filter_payload(data[key],firewall)
            for payload in payload_list:
                try:
                    data = self.parser(url,key,payload)
                    parsed_data = urlparse(url)
                    new_url = parsed_data.scheme +  "://" + parsed_data.netloc + parsed_data.path
                    if self.headers:
                        response = requests.get(new_url,params=data, headers=self.headers,verify=False).text
                    else:
                        response = requests.get(new_url, params=data,verify=False).text
                    if payload in response:
                        print(Fore.RED + f"[+] VULNERABLE: {url}\nPARAMETER: {key}\nPAYLOAD USED: {payload}")
                        print(self.replace(url,key,payload))
                        self.result.append(self.replace(url,key,payload))
                        return True
                except Exception as e:
                    print(e)
        if not threads or threads == 1:
            print(Fore.LIGHTWHITE_EX + f"[+] TARGET SEEMS TO BE NOT VULNERABLE")
        return None

if __name__ == "__main__":
    urls = []
    Scanner = Main(filename, output, headers=headers, payloads_path=payloads_path)
    try:
        if url and not filename:
            Scanner = Main(url,output,headers=headers, payloads_path=payloads_path)
            Scanner.scanner(url)
            if Scanner.result:
                Scanner.write(output,Scanner.result[0])
            exit()
        elif pipe:
            out = sys.stdin
            for url in out:
                urls.append(url)
        else:
            urls = Scanner.read(filename)
        print(Fore.GREEN + "[+] CURRENT THREADS: {}".format(threads))
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(Scanner.scanner,urls)
        for i in Scanner.result:
            Scanner.write(output,i)
        print(Fore.WHITE + "[+] COMPLETED")
    except Exception as e:
        print(e)
