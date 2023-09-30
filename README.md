## Help Panel:


AORT - All in One Recon Tool

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        domain to search its subdomains
  -o OUTPUT, --output OUTPUT
                        file to store the scan output
  -t TOKEN, --token TOKEN
                        api token of hunter.io to discover mail accounts and employees
  -p, --portscan        perform a fast and stealthy scan of the most common ports
  -m, --mail            try to enumerate mail servers
  -e, --extra           look for extra dns information
  -n, --nameservers     try to enumerate the name servers
  -i, --ip              it reports the ip or ips of the domain
  -6, --ipv6            enumerate the ipv6 of the domain
  -w, --waf             discover the WAF of the domain main page
  -s, --subtakeover     check if any of the subdomains are vulnerable to Subdomain Takeover
  -r, --repos           try to discover valid repositories and s3 servers of the domain (still improving it)
  -c, --check           check active subdomains and store them into a file
  --secrets             crawl the web page to find secrets and api keys (e.g. Google Maps API Key)
  --enum                stealthily enumerate and identify common technologies
  --whois               perform a whois query to the domain
  --wayback             find useful information about the domain and his different endpoints using The Wayback Machine and other services
  --all                 perform all the enumeration at once (best choice)
  --quiet               don't print the banner
  --version             display the script version


## Usage:

- A list of examples to use the tool in different ways 

> Most basic usage to dump all the subdomains
sh
python3 cyberfusion.py -d example.com


> Enumerate subdomains and store them in a file
sh
python3 cyberfusion.py -d example.com --output domains.txt


> Don't show banner
sh
python3 cyberfusion.py -d example.com --quiet


> Enumerate specifics things using parameters
sh
python3 cyberfusion.py -d example.com -n -p -w -b --whois --enum # You can use other parameters, see help panel


> Perform all the recon functions (recommended)
sh
python3 cyberfusion.py -d domain.com --all
