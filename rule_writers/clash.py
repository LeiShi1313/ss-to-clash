import typing
from urllib import request
from collections import defaultdict

from utils import get_rules
from rules import Region, RuleBase
from rule_writers.base import RuleWriter

header = '''
port: 7890
socks-port: 7891
redir-port: 7892
allow-lan: false
mode: {mode}
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

CUSTOM_SCRIPT = '''
allow_geo_ips = ['192.168.1.22', '192.168.1.99']
for src_ip in allow_geo_ips:
    if metadata['src_ip'] == src_ip:
      ip = ctx.resolve_ip(metadata['host'])
      code = ctx.geoip(ip)
      if code == 'CN':
        return "China"
'''

DIRECT_RULE_PROVIDERS = {
    '🏠 LocalAreaNetwork': 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/LocalAreaNetwork.yaml',
    '🏠 DirectCustom': 'https://raw.githubusercontent.com/LeiShi1313/ss-to-clash/master/Custom/Direct.yaml',
}
REJECT_RULE_PROVIDERS = {
    '🈲️ BanAD': 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/BanAD.yaml',
    # '🈲️ BanEasyList': 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/BanEasyList.yaml',
    # '🈲️ BanEasyListChina': 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/BanEasyListChina.yaml',
    # '🈲️ BanProgramAD': 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/BanProgramAD.yaml',
    # '🈲️ BanCustom': 'https://raw.githubusercontent.com/LeiShi1313/ss-to-clash/master/Custom/Ban.yaml',
}
CHINA_RULE_PROVIDERS = {
    # '🀄️ ChinaDomain': 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ChinaDomain.yaml',
    # '🀄️ ChinaCompanyIp': 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ChinaCompanyIp.yaml',
    '🀄️ ChinaIp': 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ChinaIp.yaml',
    '🀄️ ChinaCustom': 'https://raw.githubusercontent.com/LeiShi1313/ss-to-clash/master/Custom/China.yaml',
}
PROXY_RULE_PROVIDERS = {
    '✈️ ProxyLite': 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ProxyLite.yaml',
    '✈️ ProxyGFWList': 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ProxyGFWlist.yaml',
    '✈️ ProxyMedia': 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ProxyMedia.yaml',
    # '✈️ ProxyCustom': 'https://raw.githubusercontent.com/LeiShi1313/ss-to-clash/master/Custom/Proxy.yaml',
}
SCRIPT_RULE_PROVIDERS = {
    '💻 ScriptCustom': './Custom/Script.yaml',
}


class ClashWriter(RuleWriter):
    rule_name = 'clash'

    def write_header(self, f: typing.IO):
        f.write(header.format(mode=self.args.get('mode', 'Rule')))

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
            if self.args.get('node_mode') == 'fallback' or self.args.get('node_mode') == 'urltest':
                f.write(f'- name: {region}\n')
                f.write(f'  type: {self.args.get("node_mode")}\n')
                f.write(f'  url: "http://www.gstatic.com/generate_204"\n')
                f.write(f'  interval: {self.args.get("node_interval")}\n')
            else:
                f.write(f'- name: {region}\n')
                f.write(f'  type: select\n')
            f.write(f'  proxies:\n')
            for proxy in proxies:
                f.write(f'  - "{proxy.name}"\n')
            f.write('\n')

        # Write Hijack rules
        f.write('- name: Reject\n')
        f.write('  type: select\n')
        f.write('  proxies:\n')
        f.write('  - REJECT\n')
        f.write('  - DIRECT\n')

        # Write Proxy rules
        f.write('- name: Proxy\n')
        f.write('  type: select\n')
        f.write('  proxies:\n')
        f.write('  - DIRECT\n')
        for region, _ in self.proxies_by_region.items():
            f.write(f'  - {region}\n')

        # Write China rules
        f.write('- name: China\n')
        f.write('  type: select\n')
        f.write('  proxies:\n')
        if Region.CN in self.proxies_by_region:
            f.write('  - {}\n'.format(Region.CN))
        f.write('  - DIRECT\n')
        f.write('  - Proxy\n')

        # Write Speedtest rules
        if self.args.get('speedtest_rule'):
            f.write('- name: Speedtest\n')
            f.write('  type: select\n')
            f.write('  proxies:\n')
            f.write('  - DIRECT\n')
            for region, _ in self.proxies_by_region.items():
                f.write(f'  - {region}\n')

        # Write Match rules
        f.write('- name: Match\n')
        f.write('  type: select\n')
        f.write('  proxies:\n')
        f.write('  - Proxy\n')
        f.write('  - DIRECT\n')
        if Region.CN in self.proxies_by_region:
            f.write('  - {}\n'.format(Region.CN))

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

    def write_script(self, f: typing.IO):
        f.write('script:\n')
        f.write('  code: |\n')
        f.write('    def main(ctx, metadata):\n')
        f.write(f'      # Custom rules\n')
        for line in CUSTOM_SCRIPT.split('\n'):
            if len(line):
                f.write(f'      {line}\n')
        f.write(f'      # Default rules\n')
        for name in DIRECT_RULE_PROVIDERS.keys():
            f.write(f'      if ctx.rule_providers["{name}"].match(metadata):\n')
            f.write(f'        ctx.log("[Script] %s matched {name} using DIRECT" % metadata["host"])\n')
            f.write(f'        return "DIRECT"\n')
        for name in REJECT_RULE_PROVIDERS.keys():
            f.write(f'      if ctx.rule_providers["{name}"].match(metadata):\n')
            f.write(f'        ctx.log("[Script] %s matched {name} using Reject" % metadata["host"])\n')
            f.write(f'        return "Reject"\n')
        for name in CHINA_RULE_PROVIDERS.keys():
            f.write(f'      if ctx.rule_providers["{name}"].match(metadata):\n')
            f.write(f'        ctx.log("[Script] %s matched {name} using China" % metadata["host"])\n')
            f.write(f'        return "China"\n')
        for name in PROXY_RULE_PROVIDERS.keys():
            f.write(f'      if ctx.rule_providers["{name}"].match(metadata):\n')
            f.write(f'        ctx.log("[Script] %s matched {name} using Proxy" % metadata["host"])\n')
            f.write(f'        return "Proxy"\n')
        f.write(f'      return "Match"\n')
        f.write(f'rules:\n')

    def write_rules(self, f: typing.IO):
        f.write('rules:\n')

        for dest, rule_providers in zip(['DIRECT', 'Reject', 'China', 'Proxy'], [DIRECT_RULE_PROVIDERS, REJECT_RULE_PROVIDERS, CHINA_RULE_PROVIDERS, PROXY_RULE_PROVIDERS]):
            for name, rule_link in rule_providers.items():
                f.write(f'# {name}\n')
                if not self.args.get('no_rule_set'):
                    f.write(f'- RULE-SET,{name},{dest}\n')
                else:
                    for rule in get_rules(rule_link, dest, 'ip' in name.lower()):
                        f.write(f'{rule}\n')
        if self.args.get('speedtest_rule'):
            f.write('# Speedtest\n')
            f.write('- DOMAIN-KEYWORD,speedtest,Speedtest\n')

        f.write('# 其他流量\n')
        f.write('- MATCH,Match\n')

    def write(self, proxies: typing.List[RuleBase], **kwargs):
        self.args = kwargs
        self.proxies_by_region = defaultdict(list)
        for proxy in proxies:
            self.proxies_by_region[proxy.name.region].append(proxy)

        if (output_name := self.args.get('output_name')) is None:
            output_name = 'clash.yml'

        print(f"Generating clash config.")
        with open(output_name, 'w') as f:
            print(f"Writing header.")
            self.write_header(f)
            print(f"Writing dns.")
            self.write_dns(f)
            print(f"Writing proxies.")
            self.write_proxies(f)
            print(f"Writing rule providers.")
            if not self.args.get('no_rule_set'):
                self.write_rule_providers(f)
            print(f"Writing rules mode={self.args.get('mode')}.")
            if self.args.get('mode') == 'Script':
                self.write_script(f)
            else:
                self.write_rules(f)
        print(f"Done!")