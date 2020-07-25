import re
import json
import traceback
from base64 import urlsafe_b64decode
from urllib.parse import urlparse, parse_qs

from rules import RuleType, SSRRule, RuleName
from decoders.base import Decoder


class SSRDecoder1(Decoder):
    def decode(self, sub: str) -> SSRRule:
        if sub.startswith('ssr://'):
            try:
                b64_decoded = urlsafe_b64decode(sub[6:]+'==').decode('utf-8')
            except:
                return None

            if m := re.match(
                r"^(?P<server>[a-zA-Z0-9\.:]+):(?P<port>[0-9]{4,5}):(?P<protocol>[a-z0-9_]+):(?P<cipher>[a-z0-9\-]+):(?P<obfs>[a-z0-9\._]+):(?P<password>[a-zA-Z0-9]+)",
                b64_decoded):
                extram_params = parse_qs(urlparse(b64_decoded).query)
                try:
                    return SSRRule(
                        name=RuleName(urlsafe_b64decode(extram_params.get('remarks')[0]+'==').decode('utf-8')),
                        server=m.groupdict()['server'],
                        port=int(m.groupdict()['port']),
                        type=RuleType.SSR,
                        cipher=m.groupdict()['cipher'],
                        password=m.groupdict()['password'],
                        protocol=m.groupdict()['protocol'],
                        obfs=m.groupdict()['obfs'],
                        protocol_param=extram_params.get('protoparam'),
                        obfs_param=extram_params.get('obfs[aram')
                    )
                except:
                    traceback.print_exc()
                    print(sub)
        return None
