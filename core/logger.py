"""
日志管理模块
负责系统日志记录和管理
"""

import os
import logging
import logging.handlers
from pathlib import Path
from typing import Optional
from datetime import datetime

class Logger:
    """日志管理类"""
    
    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self.logger = None
        self.setup_logger()
    
    def setup_logger(self) -> None:
        """设置日志记录器"""
        # 创建日志目录
        log_file = self.config.get('file', 'data/logs/ada.log')
        log_dir = Path(log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # 配置日志级别
        level_str = self.config.get('level', 'INFO').upper()
        level = getattr(logging, level_str, logging.INFO)
        
        # 创建日志记录器
        self.logger = logging.getLogger('ADA-Framework')
        self.logger.setLevel(level)
        
        # 清除现有处理器
        self.logger.handlers.clear()
        
        # 文件处理器
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=self._parse_size(self.config.get('max_size', '10MB')),
            backupCount=self.config.get('backup_count', 5),
            encoding='utf-8'
        )
        
        # 控制台处理器
        console_handler = logging.StreamHandler()
        
        # 设置格式
        formatter = logging.Formatter(
            self.config.get('format', 
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # 添加处理器
        self.logger.addHandler(file_handler)
        
        if self.config.get('console_output', True):
            self.logger.addHandler(console_handler)
    
    def _parse_size(self, size_str: str) -> int:
        """解析大小字符串为字节数"""
        size_str = size_str.upper()
        if size_str.endswith('KB'):
            return int(size_str[:-2]) * 1024
        elif size_str.endswith('MB'):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith('GB'):
            return int(size_str[:-2]) * 1024 * 1024 * 1024
        else:
            return int(size_str)
    
    def debug(self, message: str) -> None:
        """记录调试信息"""
        if self.logger:
            self.logger.debug(message)
    
    def info(self, message: str) -> None:
        """记录信息"""
        if self.logger:
            self.logger.info(message)
    
    def warning(self, message: str) -> None:
        """记录警告"""
        if self.logger:
            self.logger.warning(message)
    
    def error(self, message: str) -> None:
        """记录错误"""
        if self.logger:
            self.logger.error(message)
    
    def critical(self, message: str) -> None:
        """记录严重错误"""
        if self.logger:
            self.logger.critical(message)
    
    def log_user_action(self, username: str, action: str, details: str = "") -> None:
        """记录用户操作"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        message = f"[USER_ACTION] {timestamp} - User: {username} - Action: {action}"
        if details:
            message += f" - Details: {details}"
        self.info(message)
    
    def log_security_event(self, event_type: str, details: str, severity: str = "INFO") -> None:
        """记录安全事件"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        message = f"[SECURITY] {timestamp} - Type: {event_type} - Severity: {severity} - Details: {details}"
        
        if severity.upper() == "CRITICAL":
            self.critical(message)
        elif severity.upper() == "ERROR":
            self.error(message)
        elif severity.upper() == "WARNING":
            self.warning(message)
        else:
            self.info(message)
    
    def log_system_event(self, event: str, details: str = "") -> None:
        """记录系统事件"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        message = f"[SYSTEM] {timestamp} - Event: {event}"
        if details:
            message += f" - Details: {details}"
        self.info(message)
    
    def get_recent_logs(self, lines: int = 100) -> list:
        """获取最近的日志记录"""
        log_file = self.config.get('file', 'data/logs/ada.log')
        
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                all_lines = f.readlines()
                return all_lines[-lines:] if len(all_lines) > lines else all_lines
        except FileNotFoundError:
            return []
        except Exception as e:
            self.error(f"读取日志文件失败: {e}")
            return []
    
    def clear_logs(self) -> bool:
        """清空日志文件"""
        log_file = self.config.get('file', 'data/logs/ada.log')
        
        try:
            with open(log_file, 'w', encoding='utf-8') as f:
                f.write("")
            self.info("日志文件已清空")
            return True
        except Exception as e:
            self.error(f"清空日志文件失败: {e}")
            return False

