import re
import json
import traceback
from base64 import urlsafe_b64decode
from urllib.parse import urlparse, parse_qs

from rules import RuleType, SSRRule, RuleName
from decoders.base import Decoder
from utils import dns_query


class SSRDecoder1(Decoder):
    def decode(self, sub: str, **kwargs) -> SSRRule:
        if sub.startswith('ssr://'):
            try:
                b64_decoded = urlsafe_b64decode(sub[6:]+'==').decode('utf-8')
            except:
                return None

            if m := re.match(
                r"^(?P<server>[a-zA-Z0-9\.\-:]+):(?P<port>[0-9]{3,5}):(?P<protocol>[a-z0-9_]+):(?P<cipher>[a-z0-9\-]+):(?P<obfs>[a-z0-9\._]+):(?P<password>[a-zA-Z0-9]+)",
                b64_decoded):
                server = dns_query(m.groupdict()['server']) if kwargs.get('use_ip', False) else m.groupdict()['server']
                port = int(m.groupdict()['port'])
                extram_params = parse_qs(urlparse(b64_decoded).query)
                if len(extram_params.get('remarks', [])):
                    name = RuleName(urlsafe_b64decode(extram_params.get('remarks')[0]+'==').decode('utf-8'), RuleType.SSR, kwargs.get('rename'))
                else:
                    name = RuleName(f'ssr://{server}:{port}', RuleType.SSR)
                protocol_param = extram_params.get('protoparam', '')
                obfs_param=urlsafe_b64decode(extram_params.get('obfsparam')[0]+'==').decode('utf-8') if extram_params.get('obfsparam') else ''
                try:
                    return SSRRule(
                        name=name,
                        type=RuleType.SSR,
                        server=server,
                        port=port,
                        cipher=m.groupdict()['cipher'],
                        password=m.groupdict()['password'],
                        protocol=m.groupdict()['protocol'],
                        obfs=m.groupdict()['obfs'],
                        protocol_param=protocol_param,
                        obfs_param=obfs_param
                    )
                except:
                    traceback.print_exc()
                    print(sub)
        return None
