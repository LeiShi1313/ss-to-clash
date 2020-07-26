import re
import typing
import base64
import argparse
import traceback
from urllib import request
from urllib.parse import unquote
from collections import defaultdict

from decoders.base import Decoder
from rule_writers.base import RuleWriter
from rules import RuleType, RuleBase, SSRule, SSRRule, Region


def decode_subs(subs: list):
    decoded_subs = []
    print(f"Decoding a total of {len(subs)} subs.")
    for line in subs:
        for decoder in Decoder.decoders:
            if (rule := decoder.decode(line)) is not None:
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
            if len(line) > 1:
                subs.append(line)

    rules = decode_subs(subs)
    RuleWriter.rule_writers[args.output_type].write(rules, **vars(args))
    # write_clash(ss_decode(subs), mode, interval)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Convert ss links to clash config.')
    parser.add_argument('ss_file_path', type=str,
                        help='按行分隔，SS链接的路径')
    parser.add_argument('output_type', type=str,
                        help='导出的配置格式，现支持clash')
    
    clash_arg_group = parser.add_argument_group('clash')
    clash_arg_group.add_argument('--output_name', type=str, default=None,
                        help='导出的配置格式名称')
    clash_arg_group.add_argument('--mode', type=str, default='Rule',
                        help='clash配置模式，默认Rule，可选Script')
    clash_arg_group.add_argument('--node-mode', type=str, default='select',
                        help='clash负载均衡配置，默认select，可选fallback/urltest')
    clash_arg_group.add_argument('--node-interval', type=int, default=600,
                        help='负载均衡的间隔，在mode选择fallback/urltest下使用，默认10分钟')
    clash_arg_group.add_argument('--rule-provider-interval', type=int, default=86400,
                        help='Rule provider间隔，默认1天')

    main(parser.parse_args())
