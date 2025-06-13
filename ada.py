#!/usr/bin/env python3
"""
ADA-ZeroDay-Framework CLI
国家级漏洞武器管理平台 - 命令行版本

主程序入口文件
"""

import sys
import os
import argparse
from pathlib import Path

# 添加项目根目录到Python路径
sys.path.insert(0, str(Path(__file__).parent))

from core.config import Config
from core.logger import Logger
from core.database import Database
from core.auth import AuthManager
from cli.parser import CLIParser
from cli.commands import CommandHandler
from cli.display import Display

__version__ = "1.0.0"
__author__ = "ADA-XiaoYao"

class ADAFramework:
    """ADA-ZeroDay-Framework 主类"""
    
    def __init__(self):
        self.config = Config()
        self.logger = Logger()
        self.database = Database()
        self.auth = AuthManager()
        self.display = Display()
        self.parser = CLIParser()
        self.commands = CommandHandler(self)
        
    def initialize(self):
        """初始化系统"""
        try:
            self.logger.info("正在初始化 ADA-ZeroDay-Framework...")
            
            # 创建必要的目录
            self._create_directories()
            
            # 初始化数据库
            self.database.initialize()
            
            # 创建默认配置
            self.config.create_default_config()
            
            self.logger.info("系统初始化完成")
            self.display.success("ADA-ZeroDay-Framework 初始化成功！")
            
        except Exception as e:
            self.logger.error(f"初始化失败: {e}")
            self.display.error(f"初始化失败: {e}")
            sys.exit(1)
    
    def _create_directories(self):
        """创建必要的目录结构"""
        directories = [
            "data",
            "data/logs",
            "data/reports",
            "data/exploits",
            "data/backups"
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
    
    def run(self, args=None):
        """运行主程序"""
        try:
            # 解析命令行参数
            parsed_args = self.parser.parse(args)
            
            # 检查是否需要初始化
            if parsed_args.command == 'init':
                self.initialize()
                return
            
            # 检查系统是否已初始化
            if not self.database.is_initialized():
                self.display.error("系统未初始化，请先运行: python ada.py init")
                sys.exit(1)
            
            # 执行命令
            self.commands.execute(parsed_args)
            
        except KeyboardInterrupt:
            self.display.warning("\n操作被用户中断")
            sys.exit(0)
        except Exception as e:
            self.logger.error(f"程序执行错误: {e}")
            self.display.error(f"执行错误: {e}")
            sys.exit(1)

def main():
    """主函数"""
    # 显示欢迎信息
    print(f"""
    ╔══════════════════════════════════════════════════════════════╗
    ║                ADA-ZeroDay-Framework CLI v{__version__}                ║
    ║              国家级漏洞武器管理平台 - 命令行版本                ║
    ║                                                              ║
    ║              自动情报 + 持久渗透 + 定点打击                    ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # 创建并运行框架实例
    framework = ADAFramework()
    framework.run()

if __name__ == "__main__":
    main()

