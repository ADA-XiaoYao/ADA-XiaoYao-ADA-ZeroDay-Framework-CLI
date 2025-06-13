#!/bin/bash

# ADA-ZeroDay-Framework CLI 安装脚本

echo "正在安装 ADA-ZeroDay-Framework CLI..."

# 检查Python版本
python_version=$(python3 --version 2>&1 | grep -Po '(?<=Python )\d+\.\d+')
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" = "$required_version" ]; then
    echo "✅ Python版本检查通过: $python_version"
else
    echo "❌ 需要Python 3.8或更高版本，当前版本: $python_version"
    exit 1
fi

# 创建虚拟环境
echo "正在创建虚拟环境..."
python3 -m venv venv

# 激活虚拟环境
echo "正在激活虚拟环境..."
source venv/bin/activate

# 升级pip
echo "正在升级pip..."
pip install --upgrade pip

# 安装依赖
echo "正在安装依赖包..."
pip install -r requirements.txt

# 创建必要的目录
echo "正在创建目录结构..."
mkdir -p data/logs
mkdir -p data/reports
mkdir -p data/exploits
mkdir -p data/backups

# 设置执行权限
chmod +x ada.py

# 初始化系统
echo "正在初始化系统..."
python ada.py init

echo ""
echo "🎉 安装完成！"
echo ""
echo "使用方法："
echo "  source venv/bin/activate  # 激活虚拟环境"
echo "  python ada.py --help      # 查看帮助"
echo "  python ada.py login --username admin  # 登录系统"
echo ""
echo "默认管理员账户："
echo "  用户名: admin"
echo "  密码: admin123"
echo ""

