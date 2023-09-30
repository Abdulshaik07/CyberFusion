import sys

# Output Colours
class c:
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    UNDERLINE = '\033[4m'

# Libraries
try:
    import requests
    import re
    import socket
    import json
    import argparse
    import platform
    import dns.zone
    import warnings
    import dns.resolver
    import pydig
    from time import sleep
    import os
    import urllib3
except Exception as e:
    print(e)
    print(c.YELLOW + "\n[" + c.RED + "-" + c.YELLOW + "] ERROR requirements missing try to install the requirements: pip3 install -r requirements.txt" + c.END)
    sys.exit(0)

# Banner Function
def banner():
    print('''
   _____      _                 ______         _             
  / ____|    | |               |  ____|       (_)            
 | |    _   _| |__   ___ _ __  | |__ _   _ ___ _  ___  _ __  
 | |   | | | | '_ \ / _ \ '__| |  __| | | / __| |/ _ \| '_ \ 
 | |___| |_| | |_) |  __/ |    | |  | |_| \__ \ | (_) | | | |
  \_____\__, |_.__/ \___|_|    |_|   \__,_|___/_|\___/|_| |_|
         __/ |                                               
        |___/                                                
        ''')
    print(c.BLUE + "\nPython version: " + c.GREEN + platform.python_version() + c.END)
    print(c.BLUE + "Current OS: " + c.GREEN + platform.system() + " " + platform.release() + c.END)

    internet_check = socket.gethostbyname(socket.gethostname())
    if internet_check == "127.0.0.1":
        if platform.system() == "Windows":
            print(c.BLUE + "Internet connection: " + c.RED + "-" + c.END)
        else:
            print(c.BLUE + "Internet connection: " + c.RED + "✕" + c.END)
    else:
        if platform.system() == "Windows":
            print(c.BLUE + "Internet connection: " + c.GREEN + "+" + c.END)
        else:
            print(c.BLUE + "Internet connection: " + c.GREEN + "✔" + c.END)

    print(c.BLUE + "Target: " + c.GREEN + domain + c.END)

# Argument parser Function
def parseArgs():
    p = argparse.ArgumentParser(description="AORT - All in One Recon Tool")
    p.add_argument("-d", "--domain", help="domain to search its subdomains", required=True)
    p.add_argument("-o", "--output", help="file to store the scan output", required=False)
    p.add_argument("-m", "--mail", help="try to enumerate mail servers", action='store_true', required=False)
    p.add_argument('-e', '--extra', help="look for extra dns information", action='store_true', required=False)
    p.add_argument("-n", "--nameservers", help="try to enumerate the name servers", action='store_true', required=False)
    p.add_argument("-i", "--ip", help="it reports the ip or ips of the domain", action='store_true', required=False)
    p.add_argument('-6', '--ipv6', help="enumerate the ipv6 of the domain", action='store_true', required=False)
    p.add_argument("-w", "--waf", help="discover the WAF of the domain main page", action='store_true', required=False)
    p.add_argument("-r", "--repos", help="try to discover valid repositories and s3 servers of the domain (still improving it)", action='store_true', required=False)
    p.add_argument("-c", "--check", help="check active subdomains and store them into a file", action='store_true', required=False)
    p.add_argument("--enum", help="stealthily enumerate and identify common technologies", action='store_true', required=False)
    p.add_argument("--whois", help="perform a whois query to the domain", action='store_true', required=False)
    p.add_argument("--all", help="perform all the enumeration at once (best choice)", action='store_true', required=False)
    p.add_argument("--quiet", help="don't print the banner", action='store_true', required=False)
    p.add_argument("--version", help="display the script version", action='store_true', required=False)
    return p.parse_args()

# Nameservers Function 
def ns_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Trying to discover valid name servers...\n" + c.END)
    sleep(0.2)
    """
    Query to get NS of the domain
    """
    data = ""
    try:
        data = dns.resolver.resolve(f"{domain}", 'NS')
    except:
        pass
    if data:
        for ns in data:
            print(c.YELLOW + str(ns) + c.END)
    else:
        print(c.YELLOW + "Unable to enumerate" + c.END)

# IPs discover Function
def ip_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Discovering IPs of the domain...\n" + c.END)
    sleep(0.2)
    """
    Query to get ips
    """
    data = ""
    try:
        data = dns.resolver.resolve(f"{domain}", 'A')
    except:
        pass
    if data:
        for ip in data:
            print(c.YELLOW + ip.to_text() + c.END)
    else:
        print(c.YELLOW + "Unable to enumerate" + c.END)

# Extra DNS info Function
def txt_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Enumerating extra DNS information...\n" + c.END)
    sleep(0.2)
    """
    Query to get extra info about the dns
    """
    data = ""
    try:
        data = dns.resolver.resolve(domain, 'TXT')
    except:
        pass
    if data:
        for info in data:
            print(c.YELLOW + info.to_text() + c.END)
    else:
        print(c.YELLOW + "Unable to enumerate" + c.END)

# Function to discover the IPv6 of the target
def ipv6_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Getting ipv6 of the domain...\n" + c.END)
    sleep(0.2)
    """
    Query to get ipv6
    """
    data = ""
    try:
        data = pydig.query(domain, 'AAAA')
    except:
        pass
    if data:
        for info in data:
            print(c.YELLOW + info + c.END)
    else:
        print(c.YELLOW + "Unable to enumerate" + c.END)

# Mail servers Function
def mail_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Finding valid mail servers...\n" + c.END)
    sleep(0.2)
    """
    Query to get mail servers
    """
    data = ""
    try:
        data = dns.resolver.resolve(f"{domain}", 'MX')
    except:
        pass
    if data:
        for server in data:
            print(c.YELLOW + str(server).split(" ")[1] + c.END)
    else:
        print(c.YELLOW + "Unable to enumerate" + c.END)

# Modified function from https://github.com/Nefcore/CRLFsuite WAF detector script <3
def wafDetector(domain):
    """
    Get WAFs list in a file
    """
    r = requests.get("https://raw.githubusercontent.com/D3Ext/AORT/main/utils/wafsign.json")
    f = open('wafsign.json', 'w')
    f.write(r.text)
    f.close()

    with open('wafsign.json', 'r') as file:
        wafsigns = json.load(file)

    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Discovering active WAF on the main web page...\n" + c.END)
    sleep(1)
    """
    Payload to trigger the possible WAF
    """
    payload = "../../../../etc/passwd"

    try:
        """
        Check the domain and modify if neccessary 
        """
        if domain.endswith("/") and domain.startswith("https://"):
            response = requests.get(domain + payload, verify=False)
        elif domain.endswith("/") and not domain.startswith("https://"):
            response = requests.get('https://' + domain + payload, verify=False)
        elif not domain.endswith("/") and domain.startswith("https://"):
            response = requests.get(domain + '/' + payload, verify=False)
        elif not domain.endswith("/") and not domain.startswith("https://"):
            response = requests.get('https://' + domain + '/' + payload, verify=False)
    except:
        print(c.YELLOW + "An error has ocurred" + c.END)
        try:
            os.remove('wafsign.json')
        except:
            pass
        return None

    code = str(response.status_code)
    page = response.text
    headers = str(response.headers)
    cookie = str(response.cookies.get_dict())
    """
    Check if WAF has blocked the request
    """
    if int(code) >= 400:
        bmatch = [0, None]
        for wafname, wafsign in wafsigns.items():
            total_score = 0
            pSign = wafsign["page"]
            cSign = wafsign["code"]
            hSign = wafsign["headers"]
            ckSign = wafsign["cookie"]
            if pSign:
                if re.search(pSign, page, re.I):
                    total_score += 1
            if cSign:
                if re.search(cSign, code, re.I):
                    total_score += 0.5
            if hSign:
                if re.search(hSign, headers, re.I):
                    total_score += 1
            if ckSign:
                if re.search(ckSign, cookie, re.I):
                    total_score += 1
            if total_score > bmatch[0]:
                del bmatch[:]
                bmatch.extend([total_score, wafname])

        if bmatch[0] != 0:
            print(c.YELLOW + bmatch[1] + c.END)
        else:
            print(c.YELLOW + "WAF not detected or doesn't exists" + c.END)
    else:
        print(c.YELLOW + "An error has ocurred or unable to enumerate" + c.END)

    try:
        os.remove('wafsign.json')
    except:
        pass


# Function to enumerate github and cloud
def cloudgitEnum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Looking for git repositories and public development info\n" + c.END)
    sleep(0.2)
    try:
        r = requests.get("https://" + domain + "/.git/", verify=False)
        print(c.YELLOW + "Git repository URL: https://" + domain + "/.git/ - " + str(r.status_code) + " status code" + c.END)
    except:
        pass
    try:
        r = requests.get("https://bitbucket.org/" + domain.split(".")[0])
        print(c.YELLOW + "Bitbucket account URL: https://bitbucket.org/" + domain.split(".")[0] + " - " + str(r.status_code) + " status code" + c.END)
    except:
        pass
    try:
        r = requests.get("https://github.com/" + domain.split(".")[0])
        print(c.YELLOW + "Github account URL: https://github.com/" + domain.split(".")[0] + " - " + str(r.status_code) + " status code" + c.END)
    except:
        pass
    try:
        r = requests.get("https://gitlab.com/" + domain.split(".")[0])
        print(c.YELLOW + "Gitlab account URL: https://gitlab.com/" + domain.split(".")[0] + " - " + str(r.status_code) + " status code" + c.END)
    except:
        pass


# Query the domain
def whoisLookup(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Performing Whois lookup..." + c.END)
    import whois
    sleep(1.2)

    try:
        w = whois.whois(domain) # Two different ways to avoid a strange error
    except:
        w = whois.query(domain)
    try:
        print(c.YELLOW + f"\n{w}" + c.END)
    except:
        print(c.YELLOW + "\nAn error has ocurred or unable to whois " + domain + c.END)

# Function to thread when probing active subdomains
def checkStatus(subdomain, file):
    try:
        r = requests.get("https://" + subdomain, timeout=2)
        # Just check if the web is up and https
        if r.status_code:
            file.write("https://" + subdomain + "\n")
    except:
        try:
            r = requests.get("http://" + subdomain, timeout=2)
            # Check if is up and http
            if r.status_code:
                file.write("http://" + subdomain + "\n")
        except:
            pass

# Check status function
def checkActiveSubs(domain,doms):
    global file
    import threading

    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Probing active subdomains..." + c.END)

    if len(doms) >= 100:
        subs_total = len(doms)
        option = input(c.YELLOW + f"\nThere are a lot of subdomains to check, ({subs_total}) do you want to check all of them [y/n]: " + c.END)
        
        if option == "n" or option == "no":
            sleep(0.2)
            return
    """ Define filename """
    domain_name = domain.split(".")[0]
    file = open(f"{domain_name}-active-subs.txt", "w")
    """
    Iterate through all subdomains in threads
    """
    threads_list = []
    for subdomain in doms:
        t = threading.Thread(target=checkStatus, args=(subdomain,file))
        t.start()
        threads_list.append(t)
    for proc_thread in threads_list: # Wait until all thread finish
        proc_thread.join()

    print(c.YELLOW + f"\nActive subdomains stored in {domain_name}-active-subs.txt" + c.END)



# Main Domain Discoverer Function
def SDom(domain,filename):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Discovering subdomains using passive techniques...\n" + c.END)
    sleep(0.1)
    global doms
    doms = []
    """
    Get valid subdomains from crt.sh
    """
    try:
        r = requests.get("https://crt.sh/?q=" + domain + "&output=json", timeout=20)
        formatted_json = json.dumps(json.loads(r.text), indent=4)
        crt_domains = sorted(set(re.findall(r'"common_name": "(.*?)"', formatted_json)))
        # Only append new valid subdomains
        for dom in crt_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)

    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass      
    """
    Get subdomains from AlienVault
    """
    try:
        r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=20)
        alienvault_domains = sorted(set(re.findall(r'"hostname": "(.*?)"', r.text)))
        # Only append new valid subdomains
        for dom in alienvault_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass
    """
    Get subdomains from Hackertarget
    """
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=20)
        hackertarget_domains = re.findall(r'(.*?),', r.text)
        # Only append new valid subdomains
        for dom in hackertarget_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)        
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass    
    """
    Get subdomains from RapidDNS
    """
    try:
        r = requests.get(f"https://rapiddns.io/subdomain/{domain}", timeout=20)
        rapiddns_domains = re.findall(r'target="_blank".*?">(.*?)</a>', r.text)
        # Only append new valid subdomains
        for dom in rapiddns_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)          
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass
    """
    Get subdomains from Riddler
    """
    try:
        r = requests.get(f"https://riddler.io/search/exportcsv?q=pld:{domain}", timeout=20)
        riddler_domains = re.findall(r'\[.*?\]",.*?,(.*?),\[', r.text)
        # Only append new valid subdomains
        for dom in riddler_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)        
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass
    """
    Get subdomains from ThreatMiner
    """
    try:
        r = requests.get(f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5", timeout=20)
        raw_domains = json.loads(r.content)
        threatminer_domains = raw_domains['results']
        # Only append new valid subdomains
        for dom in threatminer_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass
    """
    Get subdomains from URLScan
    """
    try:
        r = requests.get(f"https://urlscan.io/api/v1/search/?q={domain}", timeout=20)
        urlscan_domains = sorted(set(re.findall(r'https://(.*?).' + domain, r.text)))
        # Only append new valid subdomains
        for dom in urlscan_domains:
            dom = dom + "." + domain
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)        
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass
                
    if filename != None:
        f = open(filename, "a")
    
    if doms:
        """
        Iterate through the subdomains and check the lenght to print them in a table format
        """
        print(c.YELLOW + "+" + "-"*47 + "+")
        for value in doms:
    
            if len(value) >= 10 and len(value) <= 14:
                print("| " + value + "    \t\t\t\t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 15 and len(value) <= 19:
                print("| " + value + "\t\t\t\t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 20 and len(value) <= 24:
                print("| " + value + "   \t\t\t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 25 and len(value) <= 29:
                print("| " + value + "\t\t\t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 30 and len(value) <= 34:
                print("| " + value + " \t\t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 35 and len(value) <= 39:
                print("| " + value + "   \t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 40 and len(value) <= 44:
                print("| " + value + " \t|")
                if filename != None:
                    f.write(value + "\n")
        """
        Print summary
        """
        print("+" + "-"*47 + "+" + c.END)
        print(c.YELLOW + "\nTotal discovered sudomains: " + str(len(doms)) + c.END)
        """
        Close file if "-o" parameter was especified
        """
        if filename != None:
            f.close()
            print(c.BLUE + "\n[" + c.GREEN + "+" + c.BLUE + "] Output stored in " + filename)
    else:
        print(c.YELLOW + "No subdomains discovered through SSL transparency" + c.END)

# Check if the given target is active
def checkDomain(domain):

    try:
        addr = socket.gethostbyname(domain)
    except:
        print(c.YELLOW + "\nTarget doesn't exists or is down" + c.END)
        sys.exit(1)

# Program workflow starts here
if __name__ == '__main__':
    program_version = 1.7
    urllib3.disable_warnings()
    warnings.simplefilter('ignore')

    if "--version" in sys.argv:
        print("\nAll in One Recon Tool v" + str(program_version) + " - By D3Ext")
        print("Contact me: <d3ext@proton.me>\n")
        sys.exit(0)

    parse = parseArgs()

    # Check domain format
    if "." not in parse.domain:
        print(c.YELLOW + "\nInvalid domain format, example: domain.com" + c.END)
        sys.exit(0)

    # If --output is passed (store subdomains in file)
    if parse.output:
        store_info=1
        filename = parse.output
    else:
        filename = None

    global domain

    domain = parse.domain
    checkDomain(domain)
    """
    If --all is passed do all enumeration processes
    """
    if parse.domain and parse.all:

        if domain.startswith('https://'):
            domain = domain.split('https://')[1]
        if domain.startswith('http://'):
            domain = domain.split('http://')[1]

        try:
            if not parse.quiet:
                banner()
            SDom(domain,filename)
            ns_enum(domain)
            mail_enum(domain)
            ip_enum(domain)
            ipv6_enum(domain)
            txt_enum(domain)
            whoisLookup(domain)
            cloudgitEnum(domain)
            wafDetector(domain)
            checkActiveSubs(domain,doms)
       
            try:
                file.close()
            except:
                pass
        except KeyboardInterrupt:
            sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)

        sys.exit(0)

    """
    Enter in this part if the --all isn't passed
    """
    if parse.domain:
        domain = parse.domain

        if domain.startswith('https://'):
            domain = domain.split('https://')[1]
        if domain.startswith('http://'):
            domain = domain.split('http://')[1]

        try:
            if not parse.quiet:
                banner()
            SDom(domain,filename)
            """
            Check the passed arguments via command line
            """
         
            if parse.nameservers:
                ns_enum(domain)
            if parse.mail:
                mail_enum(domain)
            if parse.ip:
                ip_enum(domain)
            if parse.ipv6:
                ipv6_enum(domain)
            if parse.extra:
                txt_enum(domain)
            if parse.whois:
                whoisLookup(domain)
            if parse.enum:
                basicEnum(domain)
            if parse.repos:
                cloudgitEnum(domain)
            if parse.waf:
                wafDetector(domain)
            if parse.check:
                checkActiveSubs(domain,doms)

        except KeyboardInterrupt:
            sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)

