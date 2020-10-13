import json
import typing
import argparse
from urllib.request import Request, urlopen
from urllib.parse import urlencode

DEFAULT_DOH_URL = 'https://cloudflare-dns.com/dns-query'

def str2bool(v):
    if isinstance(v, bool):
       return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


def get_rules(url: str, dest: str, ipcidr: bool = False):
    rules = []
    remote_rules = urlopen(url).read().decode('utf-8')
    for line in remote_rules.split('\n'):
        if (line := line.strip().replace("'", '')).startswith('-'):
            if not ipcidr:
                if 'no-resolve' in line:
                    rules.append(f'- {",".join(line[2:].split(",")[:2])},{dest},no-resolve')
                else:
                    rules.append(f'{line},{dest}')
            else:
                rules.append(f'- IP-CIDR,{line[2:]},{dest}')
    return rules

def dns_query(url: str, doh_url: str = DEFAULT_DOH_URL) -> str:
    # TODO: Support ipv6
    params = urlencode({'name': url, 'type': 'A'})
    req = Request(f'{doh_url}?{params}', headers={'accept': 'application/dns-json'})
    result = json.loads(urlopen(req).read().decode('utf-8'))
    if not result.get('Answer'):
        return url
    # print(url, result.get('Answer', [])[-1]['data'])
    return result.get('Answer', [])[-1]['data']