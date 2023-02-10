import optparse
import ipaddress
import asyncio
import aiohttp
import os
import re
import sys
import socket
from loguru import logger
from netaddr import IPNetwork
import platform
if platform.system() == 'Windows':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

WEB_PORTS = [80, 88, 443, 7001, 8000, 8008, 8888, 8080, 8088, 8089, 8161, 9090]
OTHERS_PORTS = [21, 22, 445, 1100, 1433, 1434, 1521, 2375, 3306, 3389, 6379, 8009, 9200]

opt = None
logger.remove()
logger.add(sys.stdout, colorize=True, format="<green>{message}</green>")


def parse_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--ip", dest="ip", help="single ip or cidr; such as 1.1.1.1/24", )
    parser.add_option("-f", "--file", dest="filename", help="write report to FILE", )
    parser.add_option("-t",  "--threads", dest="threads", type='int', help="scanned threads", default=20, )
    parser.add_option("-k", "--keywords", dest="keywords", help='such as "国网,电力"',)
    parser.add_option("-q", "--quiet", action="store_true", dest="verbose", help="don't print status messages to stdout")
    parser.add_option("-d", "--depth", action="store_true", dest="depth",
                      help="scan the entire c segment of the target, otherwise scan 10 nearby ips")
    options, args = parser.parse_args()
    return options


def generate_ip_statistics_dict(ips):
    c_statistics_dict = {}
    for ip in ips:
        c = '.'.join(ip.split('.')[0:3])
        if c not in c_statistics_dict:
            c_statistics_dict[c] = []
        c_statistics_dict[c].append(ip)
    return c_statistics_dict


def nearby_ips(s, e, n=10):   # 相邻的10个ip
    s_parts = [int(x) for x in s.split(".")]
    e_parts = [int(x) for x in e.split(".")]
    start = (s_parts[3] - n) if (s_parts[3] - n) >= 0 else 0
    end = (e_parts[3] + n) if (e_parts[3] + n) <= 255 else 255
    start_ip = ".".join([str(x) for x in s_parts[0:3]]) + f'.{start}'
    end_ip = ".".join([str(x) for x in e_parts[0:3]]) + f'.{end}'
    return start_ip, end_ip


def generate_relative_cidrs(ips):
    cidrs = []
    c_statistics_dict = generate_ip_statistics_dict(ips)
    for k, v in c_statistics_dict.items():
        start_ip, end_ip = nearby_ips(v[0], v[-1])
        # print(start_ip, end_ip)
        start = ipaddress.ip_address(start_ip)
        end = ipaddress.ip_address(end_ip)
        network = list(ipaddress.summarize_address_range(start, end))[0]
        cidrs.append(str(network))
    return cidrs


def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except:
        return False


# 适配oneforall直接截取ip类
def get_ips_from_file(filepath):
    ips = []
    current_dir_path = os.path.dirname(os.path.realpath(__file__))
    filepath = os.path.join(current_dir_path, filepath)
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f.readlines():
            if line:
                line = line.strip()
                if ',' in line:         # oneforall里面有些ip带有,号，如1.1.1.1，2.2.2.2
                    for n in range(0, len(line.split(','))):
                        if is_valid_ip(line.split(',')[n]):
                            ips.append(line.split(',')[n])
                else:
                    if is_valid_ip(line):
                        ips.append(line)
    ips = list(set(ips))
    return ips


def sort_ips(ips):
    return sorted(ips, key=lambda x: int(socket.inet_aton(x).hex(), 16))


def generate_all_cidrs(ips):
    cidrs = [('.'.join(ip.split('.')[0:3]) + '.0/24') for ip in ips]
    return list(set(cidrs))


async def web_requests(ip, port):
    info = {'url':None, 'http_status': None, 'title': None, }
    async with aiohttp.ClientSession() as session:
        async with session.get(f"http://{ip}:{port}") as resp:
            html = await resp.text()
            if opt.keywords:
                result = re.findall(opt.keywords, html)
                # print(len(result))
                info['keywords'] = f'匹配到{len(result)}次'
            if html and 'title' in html:
                try:
                    info['title'] = html.split("<title>")[1].split("</title>")[0]
                except:
                    info['title'] = None
            info['http_status'] = resp.status
            info['url'] = f'http://{ip}:{port}'
            logger.info(info)


async def check_port(ip, sem):
    async with sem:
        for port in WEB_PORTS+OTHERS_PORTS:
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=0.3)
                if port in WEB_PORTS:
                    await web_requests(ip, port)
                else:
                    logger.info(f"{ip}:{port} is open.")
            except Exception as e:
                pass


async def run(ips):
    sem = asyncio.Semaphore(50)
    tasks = [asyncio.create_task(check_port(ip, sem)) for ip in ips]
    try:
        await asyncio.gather(*tasks)
    except KeyboardInterrupt:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def controller():
    global opt
    opt = parse_arguments()
    if opt.keywords:
        opt.keywords = opt.keywords.replace(',', '|')
        opt.keywords = opt.keywords.replace('，', '|')

    cidrs = []
    if opt.filename:
        ips = sort_ips(get_ips_from_file(opt.filename))
        cidrs = generate_all_cidrs(ips) if opt.depth else generate_relative_cidrs(ips)  # 这边判断ip数量 如果多于5就整段
    elif opt.ip:
        if '/' not in opt.ip:
            cidrs = ['.'.join(opt.ip.split('.')[0:3]) + '.0/24']
        else:
            cidrs = [opt.ip]

    ips = []
    for cidr in cidrs:
        ips += [str(ip) for ip in IPNetwork(cidr)]

    asyncio.run(run(ips))


if __name__ == "__main__":
    controller()

