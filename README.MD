# Cloudflare 反代 IP 发现工具使用说明

这个工具可以帮助你在本地发现和维护可用于绕过 Cloudflare 的反向代理 IP 地址。与 GitHub Actions 不同，本工具可以在你的本地环境中运行，让你完全控制扫描过程。

## 功能特点

- 多种方法发现反代 IP 地址
- 实时验证 IP 有效性
- 自动过滤 Cloudflare 官方 IP 范围
- 并发扫描提高效率
- 支持单次运行或定时运行
- 详细日志输出
- 本地存储结果

## 安装要求

1. Python 3.6 或更高版本
2. 以下 Python 库：
   - requests
   - dnspython
   - netaddr

## 安装步骤

1. 确保已安装 Python 3.6+ 环境
2. 安装依赖库：

```bash
pip install requests dnspython netaddr
```

3. 下载 `discover_cf_bypass_ips.py` 脚本到你的本地目录

## 使用方法

### 基本使用

最简单的方式是直接运行脚本：

```bash
python discover_cf_bypass_ips.py
```

这将使用默认配置开始扫描，并将结果保存到 `./output` 目录。

### 命令行参数

脚本支持多种命令行参数来定制运行方式：

```bash
python discover_cf_bypass_ips.py [选项]
```

可用选项：
- `-w, --workers` 并发线程数（默认：20）
- `-t, --timeout` 连接超时时间（秒）（默认：5）
- `-o, --output` 输出目录（默认：./output）
- `-v, --verbose` 显示详细日志
- `--schedule` 启用定时运行模式（每天运行一次）
- `--schedule-time` 定时运行的时间，格式 HH:MM（默认：00:00）

### 示例

1. 使用 50 个并发线程扫描：
```bash
python discover_cf_bypass_ips.py --workers 50
```

2. 延长超时时间到 10 秒：
```bash
python discover_cf_bypass_ips.py --timeout 10
```

3. 指定自定义输出目录：
```bash
python discover_cf_bypass_ips.py --output /path/to/my/results
```

4. 启用详细日志输出：
```bash
python discover_cf_bypass_ips.py --verbose
```

5. 每天凌晨 3 点自动运行：
```bash
python discover_cf_bypass_ips.py --schedule --schedule-time 03:00
```

## 输出文件

脚本会在输出目录中生成以下文件：

- `cloudflare_bypass_ips.json` - 完整数据的 JSON 格式
- `cloudflare_bypass_ips.txt` - 每行一个 IP 的文本文件
- `README.md` - 包含最后更新时间和统计信息
- `scan.log` - 扫描过程的详细日志
