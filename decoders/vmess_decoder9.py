import re
import json
import traceback
from base64 import urlsafe_b64decode
from urllib.parse import unquote

from rules import RuleType, VmessRule, RuleName
from decoders.base import Decoder


class VmessDecoder9(Decoder):
    def decode(self, sub: str) -> VmessRule:
        regex = re.compile(r"^vmess://(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
        if m := regex.match(sub):
            try:
                decoded_rule = json.loads(urlsafe_b64decode(sub[8:]).decode('utf-8'))
                if all(props in decoded_rule for props in ["ps", "add", "port", "id", "aid", "type"]):
                    return VmessRule(
                        name=RuleName(decoded_rule['ps']),
                        server=decoded_rule['add'],
                        port=int(decoded_rule['port']),
                        type=RuleType.VMESS,
                        uuid=decoded_rule['id'],
                        alterId=decoded_rule['aid'],
                        cipher=decoded_rule['type']
                    )
            except:
                traceback.print_exc()
                print(sub)
        return None
