"""
认证管理模块
负责用户认证、会话管理和权限控制
"""

import hashlib
import jwt
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
import bcrypt

class AuthManager:
    """认证管理类"""
    
    def __init__(self, database=None, config=None):
        self.database = database
        self.config = config or {}
        self.secret_key = self.config.get('jwt_secret_key', 'default-secret-key')
        self.algorithm = self.config.get('jwt_algorithm', 'HS256')
        self.session_timeout = self.config.get('session_timeout', 3600)
        self.max_login_attempts = self.config.get('max_login_attempts', 3)
    
    def hash_password(self, password: str) -> str:
        """哈希密码"""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """验证密码"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except:
            return False
    
    def create_user(self, username: str, password: str, email: str = "", 
                   first_name: str = "", last_name: str = "", role: str = "user") -> Optional[int]:
        """创建新用户"""
        if not self.database:
            return None
        
        # 检查用户名是否已存在
        existing_user = self.database.execute_query(
            "SELECT id FROM users WHERE username = ?", (username,)
        )
        if existing_user:
            return None
        
        # 创建用户
        user_data = {
            'username': username,
            'password_hash': self.hash_password(password),
            'email': email,
            'first_name': first_name,
            'last_name': last_name,
            'role': role,
            'is_active': True,
            'created_at': datetime.now().isoformat()
        }
        
        return self.database.insert_record('users', user_data)
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """用户认证"""
        if not self.database:
            return None
        
        # 获取用户信息
        user_result = self.database.execute_query(
            "SELECT * FROM users WHERE username = ? AND is_active = 1", (username,)
        )
        
        if not user_result:
            return None
        
        user = dict(user_result[0])
        
        # 检查登录尝试次数
        if user['login_attempts'] >= self.max_login_attempts:
            return None
        
        # 验证密码
        if not self.verify_password(password, user['password_hash']):
            # 增加登录尝试次数
            self.database.execute_update(
                "UPDATE users SET login_attempts = login_attempts + 1 WHERE id = ?",
                (user['id'],)
            )
            return None
        
        # 重置登录尝试次数并更新最后登录时间
        self.database.execute_update(
            "UPDATE users SET login_attempts = 0, last_login = ? WHERE id = ?",
            (datetime.now().isoformat(), user['id'])
        )
        
        # 移除敏感信息
        user.pop('password_hash', None)
        return user
    
    def create_session(self, user_id: int) -> Optional[str]:
        """创建用户会话"""
        if not self.database:
            return None
        
        # 生成JWT令牌
        payload = {
            'user_id': user_id,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(seconds=self.session_timeout)
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        
        # 保存会话到数据库
        session_data = {
            'user_id': user_id,
            'token': token,
            'created_at': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(seconds=self.session_timeout)).isoformat(),
            'is_active': True
        }
        
        session_id = self.database.insert_record('sessions', session_data)
        return token if session_id else None
    
    def validate_session(self, token: str) -> Optional[Dict[str, Any]]:
        """验证会话令牌"""
        if not self.database:
            return None
        
        try:
            # 解码JWT令牌
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            user_id = payload['user_id']
            
            # 检查会话是否存在且有效
            session_result = self.database.execute_query(
                "SELECT * FROM sessions WHERE token = ? AND is_active = 1 AND expires_at > ?",
                (token, datetime.now().isoformat())
            )
            
            if not session_result:
                return None
            
            # 获取用户信息
            user_result = self.database.execute_query(
                "SELECT * FROM users WHERE id = ? AND is_active = 1", (user_id,)
            )
            
            if not user_result:
                return None
            
            user = dict(user_result[0])
            user.pop('password_hash', None)
            return user
            
        except jwt.ExpiredSignatureError:
            # 令牌已过期，标记会话为无效
            self.database.execute_update(
                "UPDATE sessions SET is_active = 0 WHERE token = ?", (token,)
            )
            return None
        except jwt.InvalidTokenError:
            return None
    
    def logout(self, token: str) -> bool:
        """用户登出"""
        if not self.database:
            return False
        
        return self.database.execute_update(
            "UPDATE sessions SET is_active = 0 WHERE token = ?", (token,)
        )
    
    def check_permission(self, user: Dict[str, Any], permission: str) -> bool:
        """检查用户权限"""
        user_role = user.get('role', 'user')
        
        # 管理员拥有所有权限
        if user_role == 'admin':
            return True
        
        # 定义角色权限映射
        role_permissions = {
            'user': [
                'view_vulnerabilities',
                'view_targets',
                'view_reports'
            ],
            'analyst': [
                'view_vulnerabilities',
                'create_vulnerabilities',
                'edit_vulnerabilities',
                'view_targets',
                'create_targets',
                'view_reports',
                'create_reports'
            ],
            'operator': [
                'view_vulnerabilities',
                'create_vulnerabilities',
                'edit_vulnerabilities',
                'view_exploits',
                'create_exploits',
                'execute_exploits',
                'view_targets',
                'create_targets',
                'scan_targets',
                'view_campaigns',
                'create_campaigns',
                'execute_tasks',
                'view_reports',
                'create_reports'
            ]
        }
        
        return permission in role_permissions.get(user_role, [])
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """根据ID获取用户信息"""
        if not self.database:
            return None
        
        user_result = self.database.execute_query(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        )
        
        if user_result:
            user = dict(user_result[0])
            user.pop('password_hash', None)
            return user
        
        return None
    
    def get_all_users(self) -> List[Dict[str, Any]]:
        """获取所有用户"""
        if not self.database:
            return []
        
        users_result = self.database.execute_query(
            "SELECT id, username, email, first_name, last_name, role, is_active, created_at, last_login FROM users"
        )
        
        return [dict(user) for user in users_result]
    
    def update_user(self, user_id: int, data: Dict[str, Any]) -> bool:
        """更新用户信息"""
        if not self.database:
            return False
        
        # 如果包含密码，需要哈希
        if 'password' in data:
            data['password_hash'] = self.hash_password(data.pop('password'))
        
        data['updated_at'] = datetime.now().isoformat()
        return self.database.update_record('users', user_id, data)
    
    def delete_user(self, user_id: int) -> bool:
        """删除用户（软删除）"""
        if not self.database:
            return False
        
        return self.database.update_record('users', user_id, {
            'is_active': False,
            'updated_at': datetime.now().isoformat()
        })
    
    def reset_login_attempts(self, username: str) -> bool:
        """重置登录尝试次数"""
        if not self.database:
            return False
        
        return self.database.execute_update(
            "UPDATE users SET login_attempts = 0 WHERE username = ?", (username,)
        )
    
    def cleanup_expired_sessions(self) -> int:
        """清理过期会话"""
        if not self.database:
            return 0
        
        # 获取过期会话数量
        expired_sessions = self.database.execute_query(
            "SELECT COUNT(*) as count FROM sessions WHERE expires_at < ? AND is_active = 1",
            (datetime.now().isoformat(),)
        )
        
        count = expired_sessions[0]['count'] if expired_sessions else 0
        
        # 标记过期会话为无效
        self.database.execute_update(
            "UPDATE sessions SET is_active = 0 WHERE expires_at < ?",
            (datetime.now().isoformat(),)
        )
        
        return count

