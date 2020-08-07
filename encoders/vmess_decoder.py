import json
from urllib.parse import urlencode, quote
from base64 import urlsafe_b64encode

from encoders.base import Encoder


class SSREncoder(Encoder):
    def encode(self, sub: str, **kwargs) -> str:
        if sub.get('type') == 'vmess':
            return "vmess://" + urlsafe_b64encode(json.dumps({
                "v": "2",
                "ps": sub.get('name', ''),
                "add": sub.get('server'),
                "port": sub.get('port'),
                "host": sub.get('host', ''),
                "id": sub.get('uuid'),
                "aid": sub.get('alterId'),
                "type": sub.get('cipher'),
                "net": sub.get('network', 'tcp'),
                "tls": "tls" if sub.get('tls') else '',
                "path": sub.get('ws-path')
            }).encode('utf-8')).decode('utf-8')
        return None
