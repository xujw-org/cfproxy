#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 
# Cloudflare 反向代理 IP 发现工具
# 用于发现可用于绕过 Cloudflare 的反向代理 IP 地址
#

import requests
import json
import time
import socket
import ipaddress
import subprocess
import re
import concurrent.futures
import os
import sys
import argparse
from datetime import datetime

try:
    import dns.resolver
    from netaddr import IPNetwork, IPAddress
except ImportError:
    print("缺少必要的依赖库。请运行: pip install dnspython netaddr requests")
    sys.exit(1)

class CloudflareBypassScanner:
    def __init__(self, max_workers=20, timeout=5, output_dir="./output", verbose=False):
        """初始化扫描器"""
        self.max_workers = max_workers  # 并发线程数
        self.timeout = timeout          # 连接超时时间(秒)
        self.output_dir = output_dir    # 输出目录
        self.verbose = verbose          # 是否显示详细输出
        
        # 创建输出目录
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # 配置目标域名列表
        self.target_domains = [
            'www.cloudflare.com',      # Cloudflare 官网
            'dash.cloudflare.com',     # Cloudflare 控制面板
            'www.cloudflare-cn.com',   # Cloudflare 中国
            'one.one.one.one',         # Cloudflare DNS
            'developers.cloudflare.com', # 开发者网站
            'community.cloudflare.com', # 社区网站
        ]
        
        # 初始化 DNS 服务器列表
        self.dns_servers = ['8.8.8.8', '1.1.1.1', '114.114.114.114', '208.67.222.222']
        
        # 存储发现的有效 IP
        self.valid_bypass_ips = []
        
        # Cloudflare 已知的官方 IP 范围 (常见的)
        self.known_cf_ranges = [
            '1.1.1.0/24',       # Cloudflare DNS
            '1.0.0.0/24',       # Cloudflare 相关
            '104.16.0.0/12',    # Cloudflare 边缘网络
            '104.24.0.0/14',    # Cloudflare 边缘网络
            '108.162.192.0/18', # Cloudflare 边缘网络
            '162.158.0.0/15',   # Cloudflare 边缘网络
            '172.64.0.0/13',    # Cloudflare 边缘网络
            '173.245.48.0/20',  # Cloudflare 边缘网络
            '190.93.240.0/20',  # Cloudflare 边缘网络
            '197.234.240.0/22', # Cloudflare 边缘网络
            '198.41.128.0/17',  # Cloudflare 边缘网络
        ]
        
        # 将已知的官方 IP 范围转换为 IPNetwork 对象
        self.known_cf_networks = [IPNetwork(cidr) for cidr in self.known_cf_ranges]
    
    def log(self, message):
        """日志输出函数"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {message}")
        
        # 同时写入日志文件
        with open(f"{self.output_dir}/scan.log", "a", encoding="utf-8") as log_file:
            log_file.write(f"[{timestamp}] {message}\n")
    
    def verbose_log(self, message):
        """详细日志输出，仅在 verbose 模式下输出"""
        if self.verbose:
            self.log(message)
    
    def get_cloudflare_official_ips(self):
        """获取 Cloudflare 官方 IP 范围列表"""
        self.log("正在获取 Cloudflare 官方 IP 范围...")
        
        try:
            response = requests.get('https://api.cloudflare.com/client/v4/ips', timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    ipv4_ranges = data.get('result', {}).get('ipv4_cidrs', [])
                    ipv6_ranges = data.get('result', {}).get('ipv6_cidrs', [])
                    self.log(f"成功获取到 {len(ipv4_ranges)} 个 IPv4 范围和 {len(ipv6_ranges)} 个 IPv6 范围")
                    
                    # 将 API 获取的范围与已知范围合并
                    combined_ranges = list(set(ipv4_ranges + self.known_cf_ranges))
                    return combined_ranges, ipv6_ranges
        except Exception as e:
            self.log(f"获取 Cloudflare 官方 IP 范围失败: {e}")
        
        # 如果 API 请求失败，返回已知的 Cloudflare IP 范围
        self.log(f"使用默认的 Cloudflare IP 范围: {len(self.known_cf_ranges)} 个 IPv4 范围")
        return self.known_cf_ranges, []
    
    def get_target_real_ips(self):
        """通过多种方式获取目标域名的真实 IP 地址"""
        self.log("正在获取目标域名的真实 IP 地址...")
        all_ips = set()
        origin_server_hints = set()  # 可能的源服务器 IP
        
        for domain in self.target_domains:
            try:
                self.verbose_log(f"正在处理域名: {domain}")
                
                # 方法1: 常规 DNS 解析
                try:
                    regular_ips = socket.gethostbyname_ex(domain)[2]
                    all_ips.update(regular_ips)
                    self.verbose_log(f"常规 DNS ({domain}): {regular_ips}")
                except Exception as e:
                    self.verbose_log(f"常规 DNS 解析失败 ({domain}): {e}")
                
                # 方法2: 使用不同的 DNS 服务器
                for dns_server in self.dns_servers:
                    try:
                        resolver = dns.resolver.Resolver()
                        resolver.nameservers = [dns_server]
                        answers = resolver.resolve(domain, 'A')
                        dns_ips = [answer.address for answer in answers]
                        all_ips.update(dns_ips)
                        self.verbose_log(f"DNS 服务器 {dns_server} ({domain}): {dns_ips}")
                    except Exception as e:
                        self.verbose_log(f"DNS 服务器 {dns_server} 解析失败 ({domain}): {e}")
                
                # 方法3: 尝试通过邮件服务器、子域名等找到可能的源服务器 IP
                try:
                    # 检查是否有邮件服务器记录 (MX)
                    try:
                        mx_resolver = dns.resolver.Resolver()
                        mx_answers = mx_resolver.resolve(domain, 'MX')
                        for rdata in mx_answers:
                            mx_domain = str(rdata.exchange).rstrip('.')
                            try:
                                mx_ips = socket.gethostbyname_ex(mx_domain)[2]
                                # 邮件服务器通常与网站在同一网络，可能是源服务器的线索
                                origin_server_hints.update(mx_ips)
                                self.verbose_log(f"MX 记录 ({mx_domain}): {mx_ips}")
                            except:
                                pass
                    except:
                        pass
                    
                    # 检查是否有 TXT 记录中包含 IP
                    try:
                        txt_resolver = dns.resolver.Resolver()
                        txt_answers = txt_resolver.resolve(domain, 'TXT')
                        for rdata in txt_answers:
                            txt_value = str(rdata)
                            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                            found_ips = re.findall(ip_pattern, txt_value)
                            origin_server_hints.update(found_ips)
                            self.verbose_log(f"从 TXT 记录中发现 IP: {found_ips}")
                    except:
                        pass
                    
                    # 尝试常见的子域名，可能没有启用 Cloudflare
                    for subdomain in ['direct', 'origin', 'backend', 'cp', 'cpanel', 'server']:
                        try:
                            sub_domain = f"{subdomain}.{domain}"
                            sub_ips = socket.gethostbyname_ex(sub_domain)[2]
                            origin_server_hints.update(sub_ips)
                            self.verbose_log(f"子域名 ({sub_domain}): {sub_ips}")
                        except:
                            pass
                except:
                    pass
                
                # 方法4: 尝试 HTTP 请求可能泄露的 IP
                try:
                    headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                        'Accept': 'text/html,application/xhtml+xml,application/xml',
                        'Accept-Language': 'en-US,en;q=0.9',
                        'Accept-Encoding': 'gzip, deflate',
                        'Cache-Control': 'no-cache',
                        'Connection': 'close',
                    }
                    
                    # 尝试 HTTPS 请求
                    try:
                        response = requests.get(
                            f"https://{domain}", 
                            headers=headers, 
                            timeout=5, 
                            allow_redirects=True
                        )
                        
                        # 从响应头中查找可能的 IP
                        for header in ['X-Served-By', 'Server', 'X-Server', 'X-Host', 'X-Origin', 'X-Real-IP']:
                            if header in response.headers:
                                ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                                found_ips = re.findall(ip_pattern, response.headers[header])
                                origin_server_hints.update(found_ips)  # 这些更可能是源服务器 IP
                                self.verbose_log(f"从 HTTPS 响应头 {header} 发现 IP: {found_ips}")
                    except:
                        pass
                    
                    # 尝试 HTTP 请求
                    try:
                        response = requests.get(
                            f"http://{domain}", 
                            headers=headers, 
                            timeout=5, 
                            allow_redirects=True
                        )
                        
                        # 从响应头中查找可能的 IP
                        for header in ['X-Served-By', 'Server', 'X-Server', 'X-Host', 'X-Origin', 'X-Real-IP']:
                            if header in response.headers:
                                ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                                found_ips = re.findall(ip_pattern, response.headers[header])
                                origin_server_hints.update(found_ips)  # 这些更可能是源服务器 IP
                                self.verbose_log(f"从 HTTP 响应头 {header} 发现 IP: {found_ips}")
                    except:
                        pass
                except:
                    pass
                
            except Exception as e:
                self.log(f"获取 {domain} 的 IP 地址时出错: {e}")
        
        # 过滤掉私有 IP 和回环地址
        public_ips = []
        for ip in all_ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local):
                    public_ips.append(ip)
            except:
                pass
        
        # 过滤出可能的源服务器 IP
        public_origin_hints = []
        for ip in origin_server_hints:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local):
                    public_origin_hints.append(ip)
            except:
                pass
        
        self.log(f"成功获取到 {len(public_ips)} 个目标域名的公网 IP 和 {len(public_origin_hints)} 个可能的源服务器 IP")
        return public_ips, public_origin_hints
    
    def is_ip_in_cloudflare_networks(self, ip, cf_networks):
        """检查 IP 是否在 Cloudflare 的网络范围内"""
        try:
            ip_obj = IPAddress(ip)
            for network in cf_networks:
                if ip_obj in network:
                    return True
            return False
        except:
            return False
    
    def test_ip_for_cf_bypass(self, ip):
        """测试 IP 是否可以绕过 Cloudflare"""
        self.verbose_log(f"测试 IP: {ip}")
        
        # 首先检查 IP 是否在 Cloudflare 官方网络范围内
        if self.is_ip_in_cloudflare_networks(ip, self.known_cf_networks):
            self.verbose_log(f"IP {ip} 在 Cloudflare 官方网络范围内，跳过")
            return False
        
        try:
            # 测试连通性 (根据操作系统选择合适的 ping 命令)
            if os.name == 'nt':  # Windows
                ping_cmd = ['ping', '-n', '1', '-w', '2000', ip]
            else:  # Linux/Mac
                ping_cmd = ['ping', '-c', '1', '-W', '2', ip]
            
            result = subprocess.run(
                ping_cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                timeout=3
            )
            
            if result.returncode != 0:
                self.verbose_log(f"IP {ip} Ping 测试失败")
                return False
            
            # 测试是否可以连接到常见 Web 端口
            for port in [80, 443]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    
                    if result == 0:  # 端口开放
                        self.verbose_log(f"IP {ip} 端口 {port} 开放")
                        
                        # 尝试 HTTP(S) 请求看是否为 Cloudflare 服务器
                        protocol = 'https' if port == 443 else 'http'
                        headers = {
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                            'Host': 'www.cloudflare.com',  # 设置 Host 头
                            'Accept': 'text/html',
                            'Connection': 'close'
                        }
                        
                        # 注意：这里直接请求 IP 而不是域名
                        url = f"{protocol}://{ip}/"
                        
                        try:
                            response = requests.get(
                                url, 
                                headers=headers, 
                                timeout=self.timeout,
                                verify=False  # 忽略 SSL 证书验证
                            )
                            
                            # 检查响应是否包含 Cloudflare 特征但不是官方 Cloudflare 服务器
                            if ('cloudflare' in response.text.lower() or
                                'cf-ray' in response.headers or
                                'cf-cache-status' in response.headers):
                                
                                # 确认不是 Cloudflare 官方 IP
                                if not self.is_ip_in_cloudflare_networks(ip, self.known_cf_networks):
                                    self.verbose_log(f"IP {ip} 包含 Cloudflare 特征，是有效的反代 IP")
                                    return True
                        except:
                            pass
                except:
                    pass
        except:
            pass
        
        return False
    
    def scan_ip_range(self, ip_range, cf_networks):
        """扫描 IP 范围并测试是否为可用的 Cloudflare 反代 IP"""
        valid_ips = []
        
        for ip in ip_range:
            ip_str = str(ip)
            
            # 首先检查 IP 是否在 Cloudflare 的网络范围内
            in_cf_network = self.is_ip_in_cloudflare_networks(ip_str, cf_networks)
            
            if not in_cf_network:
                # 测试 IP 是否可用作 Cloudflare 反代
                if self.test_ip_for_cf_bypass(ip_str):
                    valid_ips.append(ip_str)
                    self.log(f"发现有效的反代 IP: {ip_str}")
        
        return valid_ips
    
    def generate_ip_range_to_scan(self, target_ip):
        """生成要扫描的 IP 范围，基于目标 IP"""
        try:
            # 将 IP 转换为网络地址对象
            ip_obj = ipaddress.ip_address(target_ip)
            ip_int = int(ip_obj)
            
            # 生成目标 IP 周围的 IP 范围
            # 1. 同一 /24 网段
            network_24 = ipaddress.ip_network(f"{target_ip}/24", strict=False)
            
            # 2. 目标 IP 周围的一小段 IP
            start_nearby = max(ip_int - 5, int(network_24.network_address))
            end_nearby = min(ip_int + 5, int(network_24.broadcast_address))
            
            # 3. 目标 IP 附近的一些随机 IP
            random_ips = []
            for offset in [-20, -10, 10, 20, 30, 40, 50]:
                random_ip = ip_int + offset
                if int(network_24.network_address) <= random_ip <= int(network_24.broadcast_address):
                    random_ips.append(ipaddress.ip_address(random_ip))
            
            # 合并扫描范围
            ip_range = []
            # 添加目标 IP 本身
            ip_range.append(ip_obj)
            # 添加目标 IP 附近的 IP
            for i in range(start_nearby, end_nearby + 1):
                ip_range.append(ipaddress.ip_address(i))
            # 添加随机 IP
            ip_range.extend(random_ips)
            
            # 去重排序
            ip_range = sorted(set(ip_range))
            
            return ip_range
        except Exception as e:
            self.verbose_log(f"生成 IP 范围时出错: {e}")
            return []
    
    def discover_bypass_ips(self):
        """发现可用的 Cloudflare 反代 IP"""
        self.log("开始发现 Cloudflare 反代 IP...")
        
        # 获取 Cloudflare 官方 IP 范围
        cf_ipv4_ranges, cf_ipv6_ranges = self.get_cloudflare_official_ips()
        
        # 将 CIDR 格式转换为 IPNetwork 对象，用于后续检查
        cf_networks = [IPNetwork(cidr) for cidr in cf_ipv4_ranges]
        
        # 获取目标域名的真实 IP 和可能的源服务器 IP
        target_ips, origin_hints = self.get_target_real_ips()
        
        # 合并两组 IP 但优先考虑可能的源服务器 IP
        scan_candidates = origin_hints + [ip for ip in target_ips if ip not in origin_hints]
        
        # 1. 先测试可能的源服务器 IP
        if origin_hints:
            self.log(f"开始测试 {len(origin_hints)} 个可能的源服务器 IP...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_ip = {executor.submit(self.test_ip_for_cf_bypass, ip): ip for ip in origin_hints}
                for future in concurrent.futures.as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        if future.result():
                            self.valid_bypass_ips.append(ip)
                            self.log(f"发现可用的反代 IP: {ip}")
                    except Exception as e:
                        self.verbose_log(f"测试 IP {ip} 时出错: {e}")
        
        # 2. 然后测试从目标域名获取的 IP
        if target_ips:
            self.log(f"开始测试 {len(target_ips)} 个目标 IP...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_ip = {executor.submit(self.test_ip_for_cf_bypass, ip): ip for ip in target_ips}
                for future in concurrent.futures.as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        if future.result():
                            self.valid_bypass_ips.append(ip)
                            self.log(f"发现可用的反代 IP: {ip}")
                    except Exception as e:
                        self.verbose_log(f"测试 IP {ip} 时出错: {e}")
        
        # 3. 智能扫描靠近目标 IP 的 IP 网段
        for target_ip in scan_candidates:
            try:
                # 确保 IP 不在 Cloudflare 网络范围内
                if not self.is_ip_in_cloudflare_networks(target_ip, cf_networks):
                    # 基于目标 IP 生成要扫描的 IP 范围
                    ip_range = self.generate_ip_range_to_scan(target_ip)
                    
                    if ip_range:
                        self.log(f"扫描 IP {target_ip} 周围的 {len(ip_range)} 个 IP...")
                        batch_results = self.scan_ip_range(ip_range, cf_networks)
                        self.valid_bypass_ips.extend(batch_results)
                        if batch_results:
                            self.log(f"在 IP {target_ip} 周围发现 {len(batch_results)} 个可用的反代 IP")
            except Exception as e:
                self.log(f"处理目标 IP {target_ip} 时出错: {e}")
        
        # 4. 扫描一些常见的云提供商 IP 段 (可能被用作 Cloudflare 反向代理)
        common_cloud_ranges = [
            # 一些常见的使用 Cloudflare 服务的网络范围 (不是 Cloudflare 自己的范围)
            '192.124.249.0/24',  # 一些托管服务商
            '193.186.32.0/24',   # 一些托管服务商
            '149.210.0.0/16',    # 一些托管服务商
            '185.116.0.0/16',    # 一些托管服务商
            '103.21.244.0/24',   # 可能的反代 IP 段
            '103.22.200.0/24',   # 可能的反代 IP 段
        ]
        
        if common_cloud_ranges:
            self.log(f"扫描 {len(common_cloud_ranges)} 个常见的云提供商 IP 段...")
            
            for cidr in common_cloud_ranges:
                try:
                    network = IPNetwork(cidr)
                    
                    # 对于每个 /24 或更大的网段，选择一些代表性 IP 进行测试
                    sample_size = 5  # 从每个范围中选择的 IP 数量
                    
                    if network.prefixlen <= 24:
                        # 如果是 /24 或更大的网段，只取样一些 IP
                        subnet_size = 2 ** (32 - network.prefixlen)
                        step = max(1, subnet_size // sample_size)
                        
                        sample_ips = []
                        for i in range(0, min(subnet_size, 100), step):
                            sample_ips.append(IPAddress(int(network.network_address) + i))
                    else:
                        # 如果是小于 /24 的网段，测试所有 IP
                        sample_ips = list(network)
                    
                    self.log(f"从 {cidr} 中选择 {len(sample_ips)} 个 IP 进行测试...")
                    
                    batch_results = self.scan_ip_range(sample_ips, cf_networks)
                    self.valid_bypass_ips.extend(batch_results)
                    
                    if batch_results:
                        self.log(f"在 {cidr} 中发现 {len(batch_results)} 个可用的反代 IP")
                except Exception as e:
                    self.log(f"处理网段 {cidr} 时出错: {e}")
        
        # 去重
        self.valid_bypass_ips = list(set(self.valid_bypass_ips))
        
        # 排序
        self.valid_bypass_ips.sort(key=lambda ip: [int(octet) for octet in ip.split('.')])
        
        self.log(f"发现过程完成，共找到 {len(self.valid_bypass_ips)} 个有效的反代 IP")
        
        return {
            "cloudflare_bypass_ips": self.valid_bypass_ips,
            "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_ips": len(self.valid_bypass_ips)
        }
    
    def write_to_files(self, data):
        """将数据写入文件"""
        if not data or not data.get('cloudflare_bypass_ips'):
            return False
        
        # 写入 JSON 文件
        json_path = os.path.join(self.output_dir, 'cloudflare_bypass_ips.json')
        with open(json_path, 'w') as json_file:
            json.dump(data, json_file, indent=2)
        
        # 写入纯文本文件
        txt_path = os.path.join(self.output_dir, 'cloudflare_bypass_ips.txt')
        with open(txt_path, 'w') as txt_file:
            txt_file.write('\n'.join(data['cloudflare_bypass_ips']))
        
        # 写入 README.md 文件
        readme_path = os.path.join(self.output_dir, 'README.md')
        readme_content = f"""# Cloudflare 反向代理 IP 列表

此仓库包含自动发现的 Cloudflare 反向代理 IP 地址列表。这些 IP 可用于直接访问 Cloudflare 保护的网站的源服务器。

最后更新时间: {data['last_updated']}

## 统计信息
- 反向代理 IP 数量: {data['total_ips']}

## 文件
- `cloudflare_bypass_ips.json`: 完整数据的 JSON 格式
- `cloudflare_bypass_ips.txt`: IP 地址列表，每行一个 IP

## 免责声明
此 IP 列表仅供研究和学习使用，不保证有效性或完整性。使用这些 IP 地址可能违反服务条款，请自行承担风险。
"""
        
        with open(readme_path, 'w') as readme_file:
            readme_file.write(readme_content)
        
        self.log(f"结果已保存到目录: {self.output_dir}")
        self.log(f"- JSON 文件: {json_path}")
        self.log(f"- 文本文件: {txt_path}")
        self.log(f"- README 文件: {readme_path}")
        
        return True
    
    def run(self):
        """运行扫描器"""
        start_time = time.time()
        self.log("Cloudflare 反向代理 IP 发现工具 - 启动")
        
        max_retries = 2
        for attempt in range(max_retries):
            try:
                self.log(f"发现 Cloudflare 反向代理 IP (尝试 {attempt+1}/{max_retries})...")
                data = self.discover_bypass_ips()
                if data and data.get('total_ips', 0) > 0 and self.write_to_files(data):
                    self.log(f"成功更新 Cloudflare 反向代理 IP 列表，共 {data['total_ips']} 个 IP")
                    break
                else:
                    self.log("更新 Cloudflare 反向代理 IP 列表失败")
                    if attempt < max_retries - 1:
                        self.log(f"等待 30 秒后重试...")
                        time.sleep(30)
            except Exception as e:
                self.log(f"错误: {e}")
                if attempt < max_retries - 1:
                    self.log(f"等待 30 秒后重试...")
                    time.sleep(30)
        
        end_time = time.time()
        elapsed_time = end_time - start_time
        self.log(f"扫描完成，总用时: {elapsed_time:.2f} 秒")

def main():
    """主函数"""
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='Cloudflare 反向代理 IP 发现工具')
    parser.add_argument('-w', '--workers', type=int, default=20, help='并发线程数 (默认: 20)')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='连接超时时间，单位秒 (默认: 5)')
    parser.add_argument('-o', '--output', type=str, default='./output', help='输出目录 (默认: ./output)')
    parser.add_argument('-v', '--verbose', action='store_true', help='显示详细日志')
    parser.add_argument('--schedule', action='store_true', help='启用定时运行模式 (每天运行一次)')
    parser.add_argument('--schedule-time', type=str, default='00:00', help='定时运行的时间，格式 HH:MM (默认: 00:00)')
    
    args = parser.parse_args()
    
    # 如果是定时运行模式
    if args.schedule:
        print(f"已启用定时运行模式，将在每天 {args.schedule_time} 运行")
        
        while True:
            # 获取当前时间
            now = datetime.now()
            schedule_hour, schedule_minute = map(int, args.schedule_time.split(':'))
            
            # 计算下次运行时间
            next_run = datetime(now.year, now.month, now.day, schedule_hour, schedule_minute)
            if now > next_run:
                next_run = datetime(now.year, now.month, now.day + 1, schedule_hour, schedule_minute)
            
            # 计算等待时间
            wait_seconds = (next_run - now).total_seconds()
            
            print(f"下次运行时间: {next_run.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"等待 {wait_seconds:.0f} 秒...")
            
            # 等待到定时时间
            time.sleep(wait_seconds)
            
            # 运行扫描器
            scanner = CloudflareBypassScanner(
                max_workers=args.workers,
                timeout=args.timeout,
                output_dir=args.output,
                verbose=args.verbose
            )
            scanner.run()
    else:
        # 直接运行一次
        scanner = CloudflareBypassScanner(
            max_workers=args.workers,
            timeout=args.timeout,
            output_dir=args.output,
            verbose=args.verbose
        )
        scanner.run()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n程序已被用户中断")
    except Exception as e:
        print(f"程序异常退出: {e}")
