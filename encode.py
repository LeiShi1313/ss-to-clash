import argparse

import yaml

from encoders.base import Encoder


def main(args):
    proxies = []
    with open(args.clash_config_path, 'r') as f:
        config = yaml.safe_load(f)
        for proxy in config.get('proxies', []):
            for encoder in Encoder.encoders:
                if (encoded_proxy := encoder.encode(proxy)) is not None:
                    proxies.append(encoded_proxy)
                    break
            else:
                print("No encoder found for: ", proxy)
    if len(proxies):
        with open(args.output_file_name, 'w') as f:
            for proxy in proxies:
                f.write(f'{proxy}\n')
        print(f'Wrote a total of {len(proxies)} proxies.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Convert clash config to ss/ssr/vmess links.')
    parser.add_argument('clash_config_path', type=str,
                        help='clash配置的路径')
    parser.add_argument('output_file_name', type=str,
                        help='保存的文件名称')

    main(parser.parse_args())
