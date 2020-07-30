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

def write_rule_from_list(self, f: typing.IO, url: str, rule_name: str):
    remote_rules = urlopen(url).read().decode('utf-8')
    for line in remote_rules.split('\n'):
        if line.startswith('#'):
            f.write(f'{line}\n')
        elif 'no-resolve' in line:
            f.write(f'- {line}\n')
        elif len(line):
            f.write(f'- {line},{rule_name}\n')

def dns_query(url: str, doh_url: str = DEFAULT_DOH_URL) -> str:
    # TODO: Support ipv6
    params = urlencode({'name': url, 'type': 'A'})
    req = Request(f'{doh_url}?{params}', headers={'accept': 'application/dns-json'})
    result = json.loads(urlopen(req).read().decode('utf-8'))
    if not result.get('Answer'):
        return url
    # print(url, result.get('Answer', [])[-1]['data'])
    return result.get('Answer', [])[-1]['data']