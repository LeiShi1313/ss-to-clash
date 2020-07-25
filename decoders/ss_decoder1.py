import re
import traceback
from base64 import urlsafe_b64decode
from urllib.parse import unquote

from rules import RuleType, SSRule, RuleName
from decoders.base import Decoder


class SSDecoder1(Decoder):
    def decode(self, sub: str) -> SSRule:
        regex = re.compile(
            r"^ss://(?P<cipher_pass>[a-zA-Z0-9]+)@(?P<server>[a-zA-Z0-9\.:]+):(?P<port>[0-9]{4,5})/\?group=(?P<group_name>[A-Z0-9]+)#(?P<name>.*)$"
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
                    RuleName(decoded_name),
                    m.groupdict().get("server"),
                    int(m.groupdict().get("port")),
                    RuleType.SS,
                    cipher,
                    passwd,
                )
            except:
                traceback.print_exc()
                print(sub)
        return None
