"""
配置管理模块
负责加载和管理系统配置
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional

class Config:
    """配置管理类"""
    
    def __init__(self, config_file: str = "config.yaml"):
        self.config_file = config_file
        self.config_data: Dict[str, Any] = {}
        self.load_config()
    
    def load_config(self) -> None:
        """加载配置文件"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.config_data = yaml.safe_load(f) or {}
            else:
                self.create_default_config()
        except Exception as e:
            print(f"加载配置文件失败: {e}")
            self.config_data = {}
    
    def create_default_config(self) -> None:
        """创建默认配置文件"""
        default_config = {
            'app': {
                'name': 'ADA-ZeroDay-Framework',
                'version': '1.0.0',
                'description': '国家级漏洞武器管理平台 - 命令行版本'
            },
            'database': {
                'type': 'sqlite',
                'path': 'data/database.db'
            },
            'logging': {
                'level': 'INFO',
                'file': 'data/logs/ada.log'
            },
            'security': {
                'session_timeout': 3600,
                'max_login_attempts': 3,
                'jwt_secret_key': 'change-this-secret-key'
            }
        }
        
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                yaml.dump(default_config, f, default_flow_style=False, allow_unicode=True)
            self.config_data = default_config
        except Exception as e:
            print(f"创建默认配置文件失败: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """获取配置值"""
        keys = key.split('.')
        value = self.config_data
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any) -> None:
        """设置配置值"""
        keys = key.split('.')
        config = self.config_data
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def save(self) -> bool:
        """保存配置到文件"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                yaml.dump(self.config_data, f, default_flow_style=False, allow_unicode=True)
            return True
        except Exception as e:
            print(f"保存配置文件失败: {e}")
            return False
    
    def get_database_config(self) -> Dict[str, Any]:
        """获取数据库配置"""
        return self.get('database', {})
    
    def get_logging_config(self) -> Dict[str, Any]:
        """获取日志配置"""
        return self.get('logging', {})
    
    def get_security_config(self) -> Dict[str, Any]:
        """获取安全配置"""
        return self.get('security', {})
    
    def get_intelligence_config(self) -> Dict[str, Any]:
        """获取情报收集配置"""
        return self.get('intelligence', {})
    
    def get_scanning_config(self) -> Dict[str, Any]:
        """获取扫描配置"""
        return self.get('scanning', {})
    
    def get_reports_config(self) -> Dict[str, Any]:
        """获取报告配置"""
        return self.get('reports', {})
    
    def validate_config(self) -> bool:
        """验证配置文件的有效性"""
        required_keys = [
            'app.name',
            'database.type',
            'database.path',
            'logging.level',
            'security.jwt_secret_key'
        ]
        
        for key in required_keys:
            if self.get(key) is None:
                print(f"配置项 {key} 缺失")
                return False
        
        return True
    
    def __str__(self) -> str:
        """返回配置的字符串表示"""
        return yaml.dump(self.config_data, default_flow_style=False, allow_unicode=True)

