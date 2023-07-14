import urllib.request

import argparse
import base64
import json
from urllib.parse import urlsplit
from copy import deepcopy
import yaml
import re
import os

GROUPS = {
    'ALL': {'香港', '台湾', '新加坡', '日本', '韩国', '美国', '英国', },
    'AMERICA': {'美国'},
    'FOREIGN': {'新加坡', '日本', '韩国', '美国', '英国', },
    'ENGLISH': {'香港', '新加坡', '美国', '英国', },
    'NETFLIX': {'新加坡', },
    'OPENAI': {'新加坡', '日本', '韩国', '美国', '英国', },
    'ASIA': {'香港', '台湾', '新加坡', '日本', '韩国', },
}
LOC_PATTERN = re.compile(r'.*({}).*'.format('|'.join(GROUPS['ALL'])))


def sub2proxies(subscribe, file=None):
    vmess_template = {'name': '',
                      'type': 'vmess',
                      'server': '',
                      'port': 80,
                      'uuid': '',
                      'alterId': 0,
                      'cipher': 'auto',
                      'network': 'ws',
                      'ws-opts': {'path': '/'},
                      'ws-path': '/',
                      'udp': True}
    proxies = []
    if file is None or not os.path.exists(file):
        headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'}
        print(subscribe)
        req = urllib.request.Request(url=subscribe, headers=headers)
        data = urllib.request.urlopen(req).read()
    else:
        with open(file, 'rb') as f:
            data = f.read()
    if file is not None:
        with open(file, 'wb') as f:
            f.write(data)
    data += b'=' * (-len(data) % 4)
    data = base64.b64decode(data).decode()
    links = data.splitlines()
    for link in links:
        node_info = urlsplit(link)
        if node_info.scheme == 'vmess':
            node_info_bytes = node_info.netloc + '=' * (4 - (len(node_info.netloc) % 4))
            node_info = json.loads(base64.b64decode(node_info_bytes).decode())
            proxy = deepcopy(vmess_template)
            proxy['name'] = node_info['ps']
            proxy['server'] = node_info['add']
            proxy['port'] = node_info['port']
            proxy['uuid'] = node_info['id']
            proxy['alterId'] = node_info['aid']
            proxy['network'] = node_info['net']
            proxy['ws-opts']['path'] = node_info['path']
            proxy['ws-path'] = node_info['path']
        elif node_info.scheme == 'ss':
            print('-' * 100)
            print(node_info)
        else:
            print('NotImplete scheme:', node_info.scheme)
            continue
        if LOC_PATTERN.match(proxy['name']):
            proxies.append(proxy)
    return proxies


def proxy2group(proxies):
    proxygroup_template = {
        'name': '',
        'type': 'url-test',
        'url': "http://www.gstatic.com/generate_204",
        'interval': 300,
        'tolerance': 50,
        'proxies': [],
    }
    proxygroups = {
        'select': {'name': 'SELECT', 'type': 'select', 'proxies': ['DIRECT']},
    }
    for group in GROUPS.keys():
        proxygroups[group] = deepcopy(proxygroup_template)
        proxygroups[group]['name'] = group

    for proxy in proxies:
        loc = LOC_PATTERN.findall(proxy['name'])[0]
        proxygroups['select']['proxies'].append(proxy['name'])
        for group, group_locs in GROUPS.items():
            if loc in group_locs:
                proxygroups[group]['proxies'].append(proxy['name'])
    return proxygroups


def proxygroup2rules(proxygroups):
    rulesets_path = 'rulesets'
    ruleprovider_template = {
        'type': 'http',
        'behavior': '',
        'url': 'https://fastly.jsdelivr.net/gh/xysyx/clash-ruleset@main',
        'path': '',
        'interval': 86400,
    }
    rules = []
    ruleproviders = {}
    for group in list(proxygroups.keys()) + ['DIRECT']:
        for behavior in ['domain', 'ipcidr']:
            ruleset_path = os.path.join(rulesets_path, behavior)
            ruleset_file = os.path.join(ruleset_path, f'{group.lower()}.yaml')
            ruleset_name = f'{behavior}-{group.lower()}'
            if os.path.exists(ruleset_file):
                ruleproviders[ruleset_name] = deepcopy(ruleprovider_template)
                ruleproviders[ruleset_name]['behavior'] = behavior
                ruleproviders[ruleset_name]['url'] = os.path.join(ruleproviders[ruleset_name]['url'], ruleset_file)
                ruleproviders[ruleset_name]['path'] = ruleset_file
                rules.append(f'RULE-SET,{ruleset_name},{group}')
    return ruleproviders, rules


def main(args):
    with open(args.clash_template, 'r') as f:
        clash_template = yaml.load(f, Loader=yaml.FullLoader)

    config = deepcopy(clash_template)
    proxies = sub2proxies(args.subscribe, args.subfile)
    config['proxies'] = proxies
    proxygroups = proxy2group(proxies)
    config['proxy-groups'] = list(proxygroups.values())
    ruleproviders, rules = proxygroup2rules(proxygroups)
    config['rule-providers'].update(ruleproviders)
    config['rules'] = rules + config['rules']
    with open(args.config, 'w') as f:
        yaml.dump(config, f, allow_unicode=True)
    print('Over')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--clash-template', '-ct', default='template/clash-config.yaml')
    parser.add_argument('--subscribe', '-sub', default=None)
    parser.add_argument('--subfile', '-sf', default=None)
    parser.add_argument('--config', '-c', default='config.yaml')
    args = parser.parse_args()
    main(args)
