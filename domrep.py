import requests
import optparse
import sys
import concurrent.futures
import socket

BLUE = '\033[94m'
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CLEAR = '\x1b[0m'

print(BLUE + "DomREP[1.0] by ARPSyndicate" + CLEAR)
print(YELLOW + "domain reputation calculator" + CLEAR)

if len(sys.argv) < 2:
    print(RED + "[!] ./domrep --help" + CLEAR)
    sys.exit()

else:
    parser = optparse.OptionParser()
    parser.add_option('-l', '--list', action="store",
                      dest="list", help="list of domains to check")
    parser.add_option('-v', '--verbose', action="store_true",
                      dest="verbose", help="enable logging", default=False)
    parser.add_option('-T', '--threads', action="store",
                      dest="threads", help="threads", default=20)
    parser.add_option('-o', '--output', action="store",
                      dest="output", help="output results")
    parser.add_option('-g', '--greynoise-key', action="store",
                      dest="gkey", help="greynoise api key")

inputs, args = parser.parse_args()
if not inputs.list:
    parser.error(RED + "[!] list of targets not given" + CLEAR)
data = str(inputs.list)
if not inputs.gkey:
    parser.error(RED + "[!] greynoise api key not given" + CLEAR)
greynoise_key = str(inputs.gkey)
verbose = inputs.verbose
output = str(inputs.output)
threads = int(inputs.threads)
result = []
with open(data) as f:
    doms = f.read().splitlines()


targets = {}


def resolv_ip(domain):
    global targets
    try:
        targets[domain] = {}
        targets[domain]['ip'] = socket.gethostbyname(domain)
    except:
        if verbose:
            print(RED + "[!] [UNRESOLVED] " + domain + CLEAR)
        targets[domain]['ip'] = "Resolution Failed"
        return
    return


def greynoise(domain):
    global targets
    if(targets[domain]['ip'] != "Resolution Failed"):
        url = "https://api.greynoise.io/v3/community/" + \
            targets[domain]['ip']
    else:
        targets[domain]["greynoise"] = 0
        return
    headers = {
        'key': greynoise_key
    }
    response = requests.request("GET", url, headers=headers).json()
    try:
        if(response["classification"] == "malicious"):
            targets[domain]["greynoise"] = 1
            if verbose:
                print(GREEN+"[*] [GREYNOISE] {0}".format(domain))
        else:
            targets[domain]["greynoise"] = 0
    except:
        targets[domain]["greynoise"] = 0
    return


def urlhaus(domain):
    global targets
    url = "https://urlhaus-api.abuse.ch/v1/host/"
    data = {
        'host': domain
    }
    responsed = requests.request("POST", url, data=data).json()
    if(responsed["query_status"] == "ok"):
        targets[domain]["urlhaus"] = 1
        if verbose:
            print(GREEN+"[*] [URLHAUS] {0}".format(domain))
    else:
        targets[domain]["urlhaus"] = 0
    if(targets[domain]['ip'] != "Resolution Failed"):
        data = {
            'host': targets[domain]['ip']
        }
        responsei = requests.request("POST", url, data=data).json()
    else:
        return
    if(responsei["query_status"] == "ok"):
        targets[domain]["urlhaus"] = 1
        if verbose:
            print(GREEN+"[*] [URLHAUS] {0}".format(domain))
    else:
        targets[domain]["urlhaus"] = 0
    return


def phishtank():
    global targets
    url = "http://data.phishtank.com/data/online-valid.json"
    response = requests.request("GET", url, allow_redirects=True).json()
    urls = []
    ips = []
    for i in range(0, len(response)):
        urls.append(response[i]['url'])
        for j in range(0, len(response[0]['details'])):
            ips.append(response[i]['details'][j]["ip_address"])
    for domain in list(targets.keys()):
        if (domain in urls or (targets[domain]['ip'] in ips and targets[domain]['ip'] != "Resolution Failed")):
            targets[domain]["phishtank"] = 1
            if verbose:
                print(GREEN+"[*] [PHISHTANK] {0}".format(domain))
        else:
            targets[domain]["phishtank"] = 0


def overall():
    global targets
    for domain in list(targets.keys()):
        avg = 0
        avg += targets[domain]["phishtank"]
        avg += targets[domain]["urlhaus"]
        avg += targets[domain]["greynoise"]
        avg = avg / 3
        targets[domain]['overall'] = "{:.2f}".format(10-avg)
        print(BLUE+"[+] [{0}] {1}".format(targets[domain]["overall"], domain))


with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
    try:
        executor.map(resolv_ip, doms)
    except(KeyboardInterrupt, SystemExit):
        print(RED + "[!] interrupted" + CLEAR)
        executor.shutdown(wait=False)
        sys.exit()

with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
    try:
        executor.map(greynoise, list(targets.keys()))
        executor.map(urlhaus, list(targets.keys()))
    except(KeyboardInterrupt, SystemExit):
        print(RED + "[!] interrupted" + CLEAR)
        executor.shutdown(wait=False)
        sys.exit()

phishtank()
overall()

if inputs.output:
    with open(output, 'a') as f:
        for domain in list(targets.keys()):
            f.writelines("[{0}] {1}\n".format(
                targets[domain]["overall"], domain))
