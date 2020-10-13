import re
import traceback
from base64 import urlsafe_b64decode
from urllib.parse import unquote

from rules import RuleType, SSRule, RuleName
from decoders.base import Decoder
from utils import dns_query


class SSDecoder1(Decoder):
    def decode(self, sub: str, **kwargs) -> SSRule:
        regex = re.compile(
            r"^ss://(?P<encrypted>[A-Za-z0-9=]+)#(?P<name>.*)$"
        )
        if m := regex.match(sub):
            try:
                decoded_name = unquote(m.groupdict().get("name"))
                decoded_proxy = urlsafe_b64decode(f"{m.groupdict().get('encrypted')}==".encode('utf-8')).decode('utf-8')
                m2 = re.match(r"^(?P<cipher>[a-z0-9\-]+):(?P<passwd>[a-zA-Z0-9\.]+)@(?P<server>[a-zA-Z0-9\-_\.]+):(?P<port>[0-9]{3,5})", decoded_proxy)
                if not m2:
                    return None
                return SSRule(
                    RuleName(decoded_name, RuleType.SS, kwargs.get('rename')),
                    RuleType.SS,
                    dns_query(m2.groupdict().get("server")) if kwargs.get('use_ip', False) else m2.groupdict().get("server"),
                    int(m2.groupdict().get("port")),
                    m2.groupdict().get("cipher"),
                    m2.groupdict().get("port"))
            except:
                traceback.print_exc()
                print(sub)
        return None
