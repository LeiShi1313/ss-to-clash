import typing
from urllib import request
from collections import defaultdict

from rules import Region, RuleBase
from rule_writers.base import RuleWriter

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
    - 114.114.114.114
    - 114.114.115.115
  fallback:
    - 1.1.1.1
'''

DIRECT_RULE_PROVIDERS = {
    '🏠 LocalAreaNetwork': 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/LocalAreaNetwork.yaml',
    '🏠 DirectCustom': 'https://raw.githubusercontent.com/LeiShi1313/ss-to-clash/master/Custom/Direct.yaml',
}
REJECT_RULE_PROVIDERS = {
    '🈲️ BanAD': 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/BanAD.yaml',
    '🈲️ BanEasyList': 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/BanEasyList.yaml',
    '🈲️ BanEasyListChina': 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/BanEasyListChina.yaml',
    '🈲️ BanProgramAD': 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/BanProgramAD.yaml',
    # '🈲️ BanCustom': 'https://raw.githubusercontent.com/LeiShi1313/ss-to-clash/master/Custom/Ban.yaml',
}
CHINA_RULE_PROVIDERS = {
    # '🀄️ ChinaDomain': 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ChinaDomain.yaml',
    # '🀄️ ChinaCompanyIp': 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ChinaCompanyIp.yaml',
    # '🀄️ ChinaIp': 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ChinaIp.yaml',
    '🀄️ ChinaCustom': 'https://raw.githubusercontent.com/LeiShi1313/ss-to-clash/master/Custom/China.yaml',
}
PROXY_RULE_PROVIDERS = {
    '✈️ ProxyLite': 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ProxyLite.yaml',
    '✈️ ProxyGFWList': 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ProxyGFWlist.yaml',
    '✈️ ProxyMedia': 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ProxyMedia.yaml',
    # '✈️ ProxyCustom': 'https://raw.githubusercontent.com/LeiShi1313/ss-to-clash/master/Custom/Proxy.yaml',
}


class ClashWriter(RuleWriter):
    rule_name = 'clash'

    def write_header(self, f: typing.IO):
        f.write(header)

    def write_dns(self, f: typing.IO):
        f.write(dns)
        f.write('\n')

    def write_proxies(self, f: typing.IO):
        f.write('proxies:\n')
        for proxies in self.proxies_by_region.values():
            for proxy in proxies:
                f.write(f"- {proxy}\n")

        f.write('\nproxy-groups:\n')
        for region, proxies in self.proxies_by_region.items():
            if self.args.get('mode') == 'fallback' or self.args.get('mode') == 'urltest':
                f.write(f'- name: {region}\n')
                f.write(f'  type: {self.args.get("mode")}\n')
                f.write(f'  url: "http://www.gstatic.com/generate_204"\n')
                f.write(f'  interval: {self.args.get("interval")}\n')
            else:
                f.write(f'- name: {region}\n')
                f.write(f'  type: select\n')
            f.write(f'  proxies:\n')
            for proxy in proxies:
                f.write(f'  - "{proxy.name}"\n')
            f.write('\n')

        # Write China rules
        if Region.CN in self.proxies_by_region:
            f.write('- name: China\n')
            f.write('  type: select\n')
            f.write('  proxies:\n')
            f.write('  - {}\n'.format(Region.CN))
            f.write('  - DIRECT\n')

        # Write Proxy rules
        f.write('- name: Proxy\n')
        f.write('  type: select\n')
        f.write('  proxies:\n')
        f.write('  - DIRECT\n')
        for region, _ in self.proxies_by_region.items():
            f.write(f'  - {region}\n')
        
        # Write Hijack rules
        f.write('- name: Reject\n')
        f.write('  type: select\n')
        f.write('  proxies:\n')
        f.write('  - REJECT\n')
        f.write('  - DIRECT\n')

        # Write Match rules
        f.write('- name: Match\n')
        f.write('  type: select\n')
        f.write('  proxies:\n')
        f.write('  - DIRECT\n')
        for region, _ in self.proxies_by_region.items():
            f.write(f'  - {region}\n')

    def write_rule_providers(self, f: typing.IO):
        f.write('rule-providers:\n')
        for rule_providers in [REJECT_RULE_PROVIDERS, CHINA_RULE_PROVIDERS, PROXY_RULE_PROVIDERS, DIRECT_RULE_PROVIDERS]:
            for name, url in rule_providers.items():
                f.write(f'  {name}:\n')
                f.write(f'    type: http\n')
                f.write(f'    url: {url}\n')
                f.write(f'    path: ./Providers/{name}.yaml\n')
                f.write(f'    interval: {self.args.get("rule_provider_interval")}\n')
                f.write(f'    behavior: {"ipcidr" if "ip" in name.lower() else "classical"}\n')
        f.write('\n')

    def write_rules(self, f: typing.IO):
        f.write('rules:\n')

        for name in REJECT_RULE_PROVIDERS.keys():
            f.write(f'# {name}\n')
            f.write(f'- RULE-SET,{name},Reject\n')
        for name in DIRECT_RULE_PROVIDERS.keys():
            f.write(f'# {name}\n')
            f.write(f'- RULE-SET,{name},DIRECT\n')
        for name in CHINA_RULE_PROVIDERS.keys():
            f.write(f'# {name}\n')
            f.write(f'- RULE-SET,{name},China\n')
        for name in PROXY_RULE_PROVIDERS.keys():
            f.write(f'# {name}\n')
            f.write(f'- RULE-SET,{name},Proxy\n')

        f.write('# 其他流量\n')
        f.write('- MATCH,Match\n')

    def write(self, proxies: typing.List[RuleBase], **kwargs):
        self.args = kwargs
        self.proxies_by_region = defaultdict(list)
        for proxy in proxies:
            self.proxies_by_region[proxy.name.region].append(proxy)

        if (output_name := self.args.get('output_name')) is None:
            output_name = 'clash.yml'

        print(f"Writing rules to {output_name}.")
        with open(output_name, 'w') as f:
            self.write_header(f)
            self.write_dns(f)
            self.write_proxies(f)
            self.write_rule_providers(f)
            self.write_rules(f)
        print(f"Done!")