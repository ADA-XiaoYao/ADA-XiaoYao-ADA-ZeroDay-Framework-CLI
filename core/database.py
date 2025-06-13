"""
数据库管理模块
负责数据库连接、表创建和数据操作
"""

import os
import sqlite3
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime
import json

class Database:
    """数据库管理类"""
    
    def __init__(self, db_path: str = "data/database.db"):
        self.db_path = db_path
        self.connection: Optional[sqlite3.Connection] = None
        self._ensure_db_directory()
    
    def _ensure_db_directory(self) -> None:
        """确保数据库目录存在"""
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
    
    def connect(self) -> sqlite3.Connection:
        """连接到数据库"""
        if self.connection is None:
            self.connection = sqlite3.connect(self.db_path)
            self.connection.row_factory = sqlite3.Row  # 使结果可以按列名访问
        return self.connection
    
    def disconnect(self) -> None:
        """断开数据库连接"""
        if self.connection:
            self.connection.close()
            self.connection = None
    
    def initialize(self) -> bool:
        """初始化数据库，创建所有必要的表"""
        try:
            conn = self.connect()
            cursor = conn.cursor()
            
            # 创建用户表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    email TEXT,
                    first_name TEXT,
                    last_name TEXT,
                    role TEXT DEFAULT 'user',
                    is_active BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    login_attempts INTEGER DEFAULT 0
                )
            ''')
            
            # 创建会话表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    token TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # 创建漏洞表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    cve_id TEXT UNIQUE,
                    description TEXT,
                    severity TEXT DEFAULT 'medium',
                    cvss_score REAL,
                    affected_systems TEXT,
                    discovery_date DATE,
                    disclosure_date DATE,
                    patch_available BOOLEAN DEFAULT 0,
                    patch_url TEXT,
                    references TEXT,
                    tags TEXT,
                    status TEXT DEFAULT 'new',
                    created_by INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (created_by) REFERENCES users (id)
                )
            ''')
            
            # 创建漏洞利用表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS exploits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    vulnerability_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    exploit_type TEXT,
                    platform TEXT,
                    code TEXT,
                    file_path TEXT,
                    reliability TEXT DEFAULT 'unknown',
                    tested BOOLEAN DEFAULT 0,
                    test_results TEXT,
                    created_by INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities (id),
                    FOREIGN KEY (created_by) REFERENCES users (id)
                )
            ''')
            
            # 创建目标表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    ip_address TEXT,
                    hostname TEXT,
                    port_range TEXT,
                    operating_system TEXT,
                    services TEXT,
                    description TEXT,
                    priority TEXT DEFAULT 'medium',
                    status TEXT DEFAULT 'active',
                    last_scan TIMESTAMP,
                    scan_results TEXT,
                    created_by INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (created_by) REFERENCES users (id)
                )
            ''')
            
            # 创建行动计划表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS campaigns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    objective TEXT,
                    start_date DATE,
                    end_date DATE,
                    status TEXT DEFAULT 'planning',
                    priority TEXT DEFAULT 'medium',
                    assigned_to INTEGER,
                    created_by INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (assigned_to) REFERENCES users (id),
                    FOREIGN KEY (created_by) REFERENCES users (id)
                )
            ''')
            
            # 创建任务表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id INTEGER,
                    title TEXT NOT NULL,
                    description TEXT,
                    task_type TEXT,
                    target_id INTEGER,
                    exploit_id INTEGER,
                    status TEXT DEFAULT 'pending',
                    priority TEXT DEFAULT 'medium',
                    scheduled_time TIMESTAMP,
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    result TEXT,
                    assigned_to INTEGER,
                    created_by INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (campaign_id) REFERENCES campaigns (id),
                    FOREIGN KEY (target_id) REFERENCES targets (id),
                    FOREIGN KEY (exploit_id) REFERENCES exploits (id),
                    FOREIGN KEY (assigned_to) REFERENCES users (id),
                    FOREIGN KEY (created_by) REFERENCES users (id)
                )
            ''')
            
            # 创建报告表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    report_type TEXT,
                    content TEXT,
                    file_path TEXT,
                    format TEXT DEFAULT 'pdf',
                    campaign_id INTEGER,
                    generated_by INTEGER,
                    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (campaign_id) REFERENCES campaigns (id),
                    FOREIGN KEY (generated_by) REFERENCES users (id)
                )
            ''')
            
            # 创建日志表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    resource_type TEXT,
                    resource_id INTEGER,
                    details TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # 创建配置表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_config (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT UNIQUE NOT NULL,
                    value TEXT,
                    description TEXT,
                    updated_by INTEGER,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (updated_by) REFERENCES users (id)
                )
            ''')
            
            conn.commit()
            return True
            
        except Exception as e:
            print(f"数据库初始化失败: {e}")
            return False
    
    def is_initialized(self) -> bool:
        """检查数据库是否已初始化"""
        try:
            conn = self.connect()
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            return cursor.fetchone() is not None
        except:
            return False
    
    def execute_query(self, query: str, params: Tuple = ()) -> List[sqlite3.Row]:
        """执行查询并返回结果"""
        try:
            conn = self.connect()
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchall()
        except Exception as e:
            print(f"查询执行失败: {e}")
            return []
    
    def execute_update(self, query: str, params: Tuple = ()) -> bool:
        """执行更新操作"""
        try:
            conn = self.connect()
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            return True
        except Exception as e:
            print(f"更新执行失败: {e}")
            return False
    
    def insert_record(self, table: str, data: Dict[str, Any]) -> Optional[int]:
        """插入记录并返回ID"""
        try:
            columns = ', '.join(data.keys())
            placeholders = ', '.join(['?' for _ in data])
            query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
            
            conn = self.connect()
            cursor = conn.cursor()
            cursor.execute(query, tuple(data.values()))
            conn.commit()
            return cursor.lastrowid
        except Exception as e:
            print(f"插入记录失败: {e}")
            return None
    
    def update_record(self, table: str, record_id: int, data: Dict[str, Any]) -> bool:
        """更新记录"""
        try:
            set_clause = ', '.join([f"{key} = ?" for key in data.keys()])
            query = f"UPDATE {table} SET {set_clause} WHERE id = ?"
            
            params = list(data.values()) + [record_id]
            return self.execute_update(query, tuple(params))
        except Exception as e:
            print(f"更新记录失败: {e}")
            return False
    
    def delete_record(self, table: str, record_id: int) -> bool:
        """删除记录"""
        try:
            query = f"DELETE FROM {table} WHERE id = ?"
            return self.execute_update(query, (record_id,))
        except Exception as e:
            print(f"删除记录失败: {e}")
            return False
    
    def get_record_by_id(self, table: str, record_id: int) -> Optional[sqlite3.Row]:
        """根据ID获取记录"""
        query = f"SELECT * FROM {table} WHERE id = ?"
        results = self.execute_query(query, (record_id,))
        return results[0] if results else None
    
    def backup_database(self, backup_path: str) -> bool:
        """备份数据库"""
        try:
            import shutil
            backup_dir = Path(backup_path).parent
            backup_dir.mkdir(parents=True, exist_ok=True)
            
            shutil.copy2(self.db_path, backup_path)
            return True
        except Exception as e:
            print(f"数据库备份失败: {e}")
            return False
    
    def restore_database(self, backup_path: str) -> bool:
        """恢复数据库"""
        try:
            import shutil
            if os.path.exists(backup_path):
                self.disconnect()
                shutil.copy2(backup_path, self.db_path)
                return True
            return False
        except Exception as e:
            print(f"数据库恢复失败: {e}")
            return False
    
    def get_database_stats(self) -> Dict[str, int]:
        """获取数据库统计信息"""
        stats = {}
        tables = ['users', 'vulnerabilities', 'exploits', 'targets', 'campaigns', 'tasks', 'reports']
        
        for table in tables:
            query = f"SELECT COUNT(*) as count FROM {table}"
            result = self.execute_query(query)
            stats[table] = result[0]['count'] if result else 0
        
        return stats
    
    def __del__(self):
        """析构函数，确保连接关闭"""
        self.disconnect()

