from urllib.parse import urlencode, quote
from base64 import urlsafe_b64encode

from encoders.base import Encoder


class SSEncoder(Encoder):
    def encode(self, sub: str, **kwargs) -> str:
        if sub.get('type') == 'ss':
            return ''.join([
                "ss://",
                urlsafe_b64encode(f"{sub.get('cipher', '')}:{sub.get('password')}".encode('utf-8')).decode('utf-8'),
                f"@{sub.get('server','')}",
                f":{sub.get('port', 0)}",
                f"#{quote(sub.get('name', ''))}"])
        return None
