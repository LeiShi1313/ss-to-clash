import typing
from urllib import request


def write_rule_from_list(self, f: typing.IO, url: str, rule_name: str):
    remote_rules = request.urlopen(url).read().decode('utf-8')
    for line in remote_rules.split('\n'):
        if line.startswith('#'):
            f.write(f'{line}\n')
        elif 'no-resolve' in line:
            f.write(f'- {line}\n')
        elif len(line):
            f.write(f'- {line},{rule_name}\n')