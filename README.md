# ss-to-clash 

## Usage 

```
python decode.py [SS-links] clash
```

## Help

```
usage: decode.py [-h] [--output_name OUTPUT_NAME] [--mode MODE] [--node-mode NODE_MODE] [--node-interval NODE_INTERVAL]
                 [--rule-provider-interval RULE_PROVIDER_INTERVAL] [--use-ip [USE_IP]]
                 ss_file_path output_type

Convert ss links to clash config.

positional arguments:
  ss_file_path          按行分隔，SS链接的路径
  output_type           导出的配置格式，现支持clash

optional arguments:
  -h, --help            show this help message and exit

clash:
  --output_name OUTPUT_NAME
                        导出的配置格式名称
  --mode MODE           clash配置模式，默认Rule，可选Script
  --node-mode NODE_MODE
                        clash负载均衡配置，默认select，可选fallback/urltest
  --node-interval NODE_INTERVAL
                        负载均衡的间隔，在mode选择fallback/urltest下使用，默认10分钟
  --rule-provider-interval RULE_PROVIDER_INTERVAL
                        Rule provider间隔，默认1天
  --use-ip [USE_IP]     是否查询并使用服务器IP地址
  ```