import re
import typing
import base64
import argparse
import requests
import traceback
from urllib.parse import unquote
from collections import defaultdict

emojis = {
    '回国': '🇨🇳',
    '阿根廷': '🇦🇷',
    '美国': '🇺🇸',
    '香港': '🇭🇰',
    '台湾': '🇹🇼',
    '日本': '🇯🇵',
    '韩国': '🇰🇷',
    '英国': '🇬🇧',
    '俄罗斯': '🇷🇺',
    '新加坡': '🇸🇬',
    '印度': '🇮🇳',
    '巴西': '🇧🇷',
}

header = '''
port: 7890
socks-port: 7891
redir-port: 7892
allow-lan: false
mode: Rule
log-level: info
external-controller: '0.0.0.0:9090'
secret: ''
'''

dns = '''
dns:
  enable: true
  nameserver:
    - https://dns.adguard.com/dns-query
  fallback:
    - 1.1.1.1
    - 8.8.8.8
    - 8.8.8.4
'''

local_and_other_rules = '''
# Local Area Network
- IP-CIDR,192.168.0.0/16,DIRECT
- IP-CIDR,10.0.0.0/8,DIRECT
- IP-CIDR,172.16.0.0/12,DIRECT
- IP-CIDR,127.0.0.0/8,DIRECT
- IP-CIDR,100.64.0.0/10,DIRECT
 
# 其他流量
- MATCH,Match
'''

china_rule_lists = [
    'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Bilibili.list',
    'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/NetEaseMusic.list',
    'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Tencent.list',
    'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/TencentVideo.list',
    'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Alibaba.list',
    'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Ximalaya.list',
    'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Youku.list',
    'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Iqiyi.list',
    'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaMedia.list',
    'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaDomain.list'
]
gfw_rule_lists = [
    'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ProxyGFWlist.list',
    'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ProxyMedia.list',
]

def ss_sub_decode(ss_sub: str) -> dict:
    ss_sub_decoded = base64.b64decode(ss_sub + '==').decode('utf-8')
    regex = re.compile(r'(?P<cipher>[a-zA-Z0-9\-]+):(?P<password>[a-zA-Z0-9]+)@(?P<server>[a-zA-Z0-9\.\-_:]+):(?P<port>[0-9]+)$')
    if m := regex.match(ss_sub_decoded):
        return m.groupdict()
    else:
        raise ValueError(f"Not a valid SS subscription: {ss_sub}")

def get_sub_name(raw) -> str:
    return unquote(raw).strip('ssrcloud -').strip('中国-').strip()

def ss_decode(subs: list) -> dict:
    print('Start decoding ss subscriptions...')
    regex = re.compile(r'ss://(?P<ss_sub>[a-zA-Z0-9]+)#(?P<name>.*)$')
    group_by_country = defaultdict(list)
    count = 0
    for line in subs:
        if m := regex.match(line):
            try:
                clash_rule = {'name': get_sub_name(m.groupdict().get('name')), 'type': 'ss'}
                clash_rule.update(ss_sub_decode(m.groupdict().get('ss_sub')))
                if clash_rule.get('server') == '127.0.0.1':
                    continue
                for c, emoji in emojis.items():
                    if c in clash_rule.get('name'):
                        clash_rule['name'] = emoji + '  ' + clash_rule['name']
                        group_by_country[c].append(clash_rule)
                        count += 1
            except:
                traceback.print_exc()
                print(line)
    print(f'A total of {count} subscriptions found')
    return group_by_country

def write_rule_from_list(f: typing.IO, list_url: str, rule_name: str):
    remote_rule = requests.get(list_url)
    for line in remote_rule.text.split('\n'):
        if line.startswith('#'):
            f.write(f'{line}\n')
        elif line.startswith('USER-AGENT'):
            continue
        elif len(line):
            f.write(f'- {line.strip(",no-resolve")},{rule_name}\n')

def write_clash(group_by_country: dict, mode='select', interval=600):
    print('Start writing clash config...')
    with open('clash.yml', 'w') as f:
        # Write header
        f.write(header)
        # Write DNS
        f.write(dns)

        # Write proxies
        f.write('proxies:\n')
        for _, subs in group_by_country.items():
            for sub in subs:
                f.write(f'- {sub}\n')
        f.write('\n')

        # Write proxy groups
        f.write('proxy-groups:\n')
        for country, subs in group_by_country.items():
            if mode == 'select':
                f.write(f'- name: {country}\n')
                f.write(f'  type: select\n')
            elif mode == 'fallback':
                f.write(f'- name: {country}\n')
                f.write(f'  type: fallback\n')
                f.write(f'  url: "http://www.gstatic.com/generate_204"\n')
                f.write(f'  interval: {interval}\n')
            else:
                f.write(f'- name: {country}\n')
                f.write(f'  type: urltest\n')
                f.write(f'  url: "http://www.gstatic.com/generate_204"\n')
                f.write(f'  interval: {interval}\n')
            f.write(f'  proxies:\n')
            for sub in subs:
                f.write(f'  - {sub["name"]}\n')
            f.write('\n')

        # Write China rules
        f.write('- name: China\n')
        f.write('  type: select\n')
        f.write('  proxies:\n')
        f.write('  - DIRECT\n')
        f.write('  - 回国\n')

        # Write Proxy rules
        f.write('- name: Proxy\n')
        f.write('  type: select\n')
        f.write('  proxies:\n')
        f.write('  - DIRECT\n')
        for country, _ in group_by_country.items():
            f.write(f'  - {country}\n')

        # Write Match rules
        f.write('- name: Match\n')
        f.write('  type: select\n')
        f.write('  proxies:\n')
        f.write('  - DIRECT\n')
        for country, _ in group_by_country.items():
            f.write(f'  - {country}\n')
            

        # Write rules
        # Write China rules
        f.write('rules:\n')
        for rule_list in china_rule_lists:
            write_rule_from_list(f, rule_list, 'China')
        for rule_list in gfw_rule_lists:
            write_rule_from_list(f, rule_list, 'Proxy')
        f.write(local_and_other_rules)
    print('Completed!')



def main(ss_file_path, mode, interval):
    subs = []
    with open(ss_file_path, 'r') as f:
        for line in f.readlines():
            subs.append(line)

    write_clash(ss_decode(subs), mode, interval)

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Convert ss links to clash config.')
    parser.add_argument('ss_file_path', type=str, 
                    help='按行分隔，SS链接的路径')
    parser.add_argument('--mode', type=str, default='select',
                    help='clash负载均衡配置，默认select，可选fallback/urltest')
    parser.add_argument('--interval', type=int, default='600',
                    help='负载均衡的间隔，在mode选择fallback/urltest下使用，默认10分钟')

    args = parser.parse_args()
    main(args.ss_file_path, args.mode, args.interval)