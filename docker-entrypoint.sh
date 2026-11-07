#!/bin/sh
# 入口脚本仅做 exec 转发，保证 `docker run <image> -c /etc/honeypot.yaml` 原生命令行用法不变；
# 环境变量到配置的映射（AI_* 10 项 + WEB_TRUSTED_PROXIES）已内置于二进制，脚本不再翻译。
set -e
exec /app/honeypot "$@"
