from urllib.parse import urlencode, quote
from base64 import urlsafe_b64encode

from encoders.base import Encoder


class SSREncoder(Encoder):
    def encode(self, sub: str, **kwargs) -> str:
        if sub.get('type') == 'ssr':
            return "ssr://" + urlsafe_b64encode(
                ''.join([
                    sub.get('server', ''),
                    f":{sub.get('port', 0)}",
                    f":{sub.get('protocol', '')}",
                    f":{sub.get('cipher', '')}",
                    f":{sub.get('obfs', '')}",
                    f":{sub.get('password', '')}",
                    "/?",
                    urlencode({
                        'obfsparam': urlsafe_b64encode(sub.get('obfs-param', '').encode('utf-8')).decode('utf-8'),
                        'protoparam': urlsafe_b64encode(sub.get('protocol-param', '').encode('utf-8')).decode('utf-8'),
                        'remarks': urlsafe_b64encode(sub.get('name', '').encode('utf-8')).decode('utf-8'),
                        'group': urlsafe_b64encode(sub.get('group', '').encode('utf-8')).decode('utf-8'),
                    })
                ]).encode('utf-8')).decode('utf-8')
        return None
