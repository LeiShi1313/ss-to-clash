import re
import typing
import base64
import argparse
import traceback
from urllib import request
from urllib.parse import unquote
from collections import defaultdict

from utils import str2bool
from decoders.base import Decoder
from rule_writers.base import RuleWriter
from rules import RuleType, RuleBase, SSRule, SSRRule, Region


def decode_subs(subs: list, **kwargs):
    decoded_subs = []
    hashed_subs = set()
    hashed_names = set()
    print(f"Decoding a total of {len(subs)} subs.")
    if kwargs.get('use_ip'):
        print(f"Use ip turned on, this will take a while...")
    for line in subs:
        if line.startswith('#'):
            continue
        for decoder in Decoder.decoders:
            if (rule := decoder.decode(line, **kwargs)) is not None:
                if rule.get_hash() not in hashed_subs:
                    if str(rule.name) in hashed_names:
                        print(f'{rule} has duplicated name, skippping...')
                        continue
                    hashed_subs.add(rule.get_hash())
                    hashed_names.add(str(rule.name))
                    decoded_subs.append(rule)
                break
        else:
            print(f"No decoder found for sub: {line}")
    print(f"Found {len(decoded_subs)} subs.")
    return decoded_subs


def main(args):
    subs = []
    with open(args.ss_file_path, 'r') as f:
        for line in f.readlines():
            line = line.strip()
            if len(line) > 1:
                subs.append(line)

    rules = decode_subs(subs, **vars(args))
    RuleWriter.rule_writers[args.output_type].write(rules, **vars(args))
    # write_clash(ss_decode(subs), mode, interval)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Convert ss links to clash config.')
    parser.add_argument('ss_file_path', type=str,
                        help='按行分隔，SS链接的路径')
    parser.add_argument('output_type', type=str,
                        help='导出的配置格式，现支持clash')
    
    clash_arg_group = parser.add_argument_group('clash')
    clash_arg_group.add_argument('--output-name', type=str, default=None,
                        help='导出的配置格式名称')
    clash_arg_group.add_argument('--mode', type=str, default='Rule',
                        help='clash配置模式，默认Rule，可选Script')
    clash_arg_group.add_argument('--node-mode', type=str, default='select',
                        help='clash负载均衡配置，默认select，可选fallback/urltest')
    clash_arg_group.add_argument('--node-interval', type=int, default=600,
                        help='负载均衡的间隔，在mode选择fallback/urltest下使用，默认10分钟')
    clash_arg_group.add_argument('--rule-provider-interval', type=int, default=86400,
                        help='Rule provider间隔，默认1天')
    clash_arg_group.add_argument('--use-ip', type=str2bool, nargs='?', const=True, default=False,
                        help='是否查询并使用服务器IP地址')
    clash_arg_group.add_argument('--no-rule-set', type=str2bool, nargs='?', const=True, default=False,
                        help='是否使用RULE-SET')
    clash_arg_group.add_argument('--speedtest-rule', type=str2bool, nargs='?', const=True, default=False,
                        help='是否添加speedtest专用规则')
    clash_arg_group.add_argument('--rename', type=int, nargs='?', const=1, default=0,
                        help='是否重命名节点，2则在原有名称最后按地区，默认(1)则按`emoji 地区 001`格式重命名节点')


    main(parser.parse_args())
