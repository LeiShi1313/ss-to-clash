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
            r"^ss://(?P<cipher_pass>[a-zA-Z0-9=]+)@(?P<server>[a-zA-Z0-9\.:]+):(?P<port>[0-9]{4,5}).*#(?P<name>.*)$"
        )
        if m := regex.match(sub):
            try:
                decoded_name = unquote(m.groupdict().get("name"))
                cipher, passwd = (
                    urlsafe_b64decode(m.groupdict().get("cipher_pass") + "==")
                    .decode("utf-8")
                    .split(":")
                )
                return SSRule(
                    RuleName(decoded_name, RuleType.SS, kwargs.get('rename')),
                    RuleType.SS,
                    dns_query(m.groupdict().get("server")) if kwargs.get('use_ip', False) else m.groupdict().get("server"),
                    int(m.groupdict().get("port")),
                    cipher,
                    passwd,
                )
            except:
                traceback.print_exc()
                print(sub)
        return None
