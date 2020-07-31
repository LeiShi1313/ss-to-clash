import json
from enum import Enum, unique
from dataclasses import dataclass


@unique
class RuleType(Enum):
    UNKNOWN = 'UNKNOWN'
    SS = 'ss'
    SSR = 'ssr'
    VMESS = 'vmess'
    TROJAN = 'trojan'
    SOCKS = 'socks'
    HTTP = 'http'

    def __str__(self):
        return self.value


@unique
class Region(Enum):
    UNKNOWN = ('UNKNOWN', '未知', 0)
    CN = ('🇨🇳', '中国', 1)
    HK = ('🇭🇰', '香港', 2)
    TW = ('🇹🇼', '台湾', 3)
    JP = ('🇯🇵', '日本', 4)
    KR = ('🇰🇷', '韩国', 5)
    US = ('🇺🇸', '美国', 6)
    SG = ('🇸🇬', '新加坡', 7)
    EU = ('🇪🇺', '欧洲', 8)
    AR = ('🇦🇷', '阿根廷', 9)
    RU = ('🇷🇺', '俄罗斯', 10)
    IN = ('🇮🇳', '印度', 11)
    BR = ('🇧🇷', '巴西', 12)
    OTHERS = ('😯', '其他', 13)

    def __str__(self):
        return f"{self.value[0]} {self.value[1]}"


class RuleName:
    def __init__(self, name, rule_type: RuleType):
        self.original_name = name.strip(" \t\n")
        self.region = RuleName.get_region(name)
        self.name = RuleName.stripe_name(name)
        self.rule_type = rule_type

    @classmethod
    def get_region(cls, name: str) -> Region:
        patterns_by_tier = [[
            (["深圳香港", "中国-香港", "中国香港", "香港", "Hong Kong", "HK"], Region.HK),
            (["中国-台湾", "台湾", "台灣", "TW"], Region.TW),
            (["中国-日本", "日本", "JP"], Region.JP),
            (["中国-韩国", "韩国", "韓國", "KR"], Region.KR),
            (["中国-美国", "美国", "美國", "USA", " US "], Region.US),
            (["中国-新加坡", "新加坡", "SG"], Region.SG),
            (["中国-英国", "英国", "英國", "法国", "法國", "意大利", "義大利", "德国", "德國"], Region.EU),
            (["中国-阿根廷", "阿根廷"], Region.AR),
            (["中国-俄罗斯", "俄罗斯", "俄羅斯"], Region.RU),
            (["中国-印度", "印度"], Region.IN),
            (["中国-巴西", "巴西"], Region.BR)
        ], [
            (["回国"], Region.CN)
        ]]

        for tier_patterns in patterns_by_tier:
            for patterns, region in tier_patterns:
                if any(pattern in name for pattern in patterns):
                    return region
        return Region.OTHERS

    @classmethod
    def stripe_name(cls, name: str) -> str:
        replace_rules = ['CNIX - ', 'ssrcloud - ', '\t', '/']
        for rule in replace_rules:
            name = name.replace(rule, '')
        return name.strip()

    def __repr__(self) -> str:
        return f"{self.region.value[0]} {self.name} {self.rule_type.value.upper()}"


@dataclass
class RuleBase:
    name: RuleName
    type: RuleType
    server: str
    port: int

    def get_hash(self):
        return hash(f'{self.type}://{self.server}:{self.port}')


@dataclass
class SSRule(RuleBase):
    cipher: str
    password: str

    def __repr__(self):
        return json.dumps({
            'name': str(self.name),
            'type': self.type.value,
            'server': self.server,
            'port': self.port,
            'cipher': self.cipher,
            'password': self.password
        }, ensure_ascii=False)


@dataclass
class SSRRule(RuleBase):
    cipher: str
    password: str
    protocol: str
    obfs: str
    protocol_param: str = ''
    obfs_param: str = None

    def __repr__(self):
        return json.dumps({
                k.replace('_', '-'): v if isinstance(v, int) else str(v)
                for k,v in self.__dict__.items() if v is not None
            }, ensure_ascii=False)


@dataclass
class VmessRule(RuleBase):
    uuid: str
    alterId: int
    cipher: str
    tls: bool = None
    udp: bool = None
    network: str = None
    ws_path: str = None
    ws_headers: dict = None

    def __repr__(self):
        return json.dumps({
                k.replace('_', '-'): v if isinstance(v, int) else str(v)
                for k,v in self.__dict__.items() if v is not None
            }, ensure_ascii=False)
