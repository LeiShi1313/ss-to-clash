import re
import json
import traceback
from base64 import urlsafe_b64decode
from urllib.parse import unquote

from rules import RuleType, VmessRule, RuleName
from decoders.base import Decoder
from utils import dns_query


class VmessDecoder9(Decoder):
    def decode(self, sub: str, **kwargs) -> VmessRule:
        regex = re.compile(r"^vmess://(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
        if m := regex.match(sub):
            try:
                decoded_rule = json.loads(urlsafe_b64decode(sub[8:]).decode('utf-8'))
                extra_params = {
                    'network': decoded_rule.get('net'),
                    'ws_path': decoded_rule.get('path'),
                    'tls': any(t == decoded_rule.get('tls') for t in [True, 'tls', 'true']),
                    'udp': any(t == decoded_rule.get('udp') for t in [True, 'true']),
                }
                if all(props in decoded_rule for props in ["ps", "add", "port", "id", "aid", "type"]):
                    return VmessRule(
                        name=RuleName(decoded_rule['ps'], RuleType.VMESS, kwargs.get('rename')),
                        type=RuleType.VMESS,
                        server=dns_query(decoded_rule['add']) if kwargs.get('use_ip', False) else decoded_rule['add'],
                        port=int(decoded_rule['port']),
                        uuid=decoded_rule['id'],
                        alterId=decoded_rule['aid'],
                        cipher=decoded_rule['type'],
                        **{k:v for k,v in extra_params.items() if v is not None}
                    )
            except:
                traceback.print_exc()
                print(sub)
        return None
