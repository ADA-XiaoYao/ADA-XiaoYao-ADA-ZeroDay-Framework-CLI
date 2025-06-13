"""
命令处理模块
负责处理各种CLI命令的执行
"""

import os
import sys
import getpass
from typing import Any, Dict, Optional
from datetime import datetime

from core.config import Config
from core.database import Database
from core.auth import AuthManager
from core.logger import Logger
from modules.vulnerability import VulnerabilityManager
from cli.display import Display

class CommandHandler:
    """命令处理器"""
    
    def __init__(self, framework):
        self.framework = framework
        self.config = framework.config
        self.database = framework.database
        self.auth = framework.auth
        self.logger = framework.logger
        self.display = framework.display
        
        # 初始化模块
        self.vuln_manager = VulnerabilityManager(self.database, self.logger)
        
        # 当前用户会话
        self.current_user = None
        self.current_token = None
        
        # 加载保存的会话
        self._load_session()
    
    def execute(self, args: Any) -> None:
        """执行命令"""
        command = args.command
        
        if command == 'login':
            self._handle_login(args)
        elif command == 'logout':
            self._handle_logout(args)
        elif command == 'status':
            self._handle_status(args)
        elif command == 'user':
            self._handle_user(args)
        elif command == 'vuln':
            self._handle_vulnerability(args)
        elif command == 'target':
            self._handle_target(args)
        elif command == 'campaign':
            self._handle_campaign(args)
        elif command == 'task':
            self._handle_task(args)
        elif command == 'report':
            self._handle_report(args)
        elif command == 'intel':
            self._handle_intelligence(args)
        elif command == 'maintenance':
            self._handle_maintenance(args)
        else:
            self.display.error(f"未知命令: {command}")
    
    def _handle_login(self, args: Any) -> None:
        """处理登录命令"""
        username = args.username
        password = args.password
        
        if not password:
            password = self.display.prompt_input("请输入密码", password=True)
        
        # 认证用户
        user = self.auth.authenticate_user(username, password)
        if not user:
            self.display.error("登录失败：用户名或密码错误")
            return
        
        # 创建会话
        token = self.auth.create_session(user['id'])
        if not token:
            self.display.error("创建会话失败")
            return
        
        # 保存会话信息
        self.current_user = user
        self.current_token = token
        self._save_session()
        
        self.display.success(f"登录成功！欢迎 {user['username']} ({user['role']})")
        self.logger.log_user_action(username, "login", "User logged in successfully")
    
    def _handle_logout(self, args: Any) -> None:
        """处理登出命令"""
        if not self.current_token:
            self.display.warning("您尚未登录")
            return
        
        # 登出
        self.auth.logout(self.current_token)
        
        username = self.current_user['username'] if self.current_user else "unknown"
        self.current_user = None
        self.current_token = None
        self._clear_session()
        
        self.display.success("已成功登出")
        self.logger.log_user_action(username, "logout", "User logged out")
    
    def _handle_status(self, args: Any) -> None:
        """处理状态命令"""
        self.display.print_header("系统状态")
        
        # 数据库状态
        db_stats = self.database.get_database_stats()
        self.display.print_stats(db_stats, "数据库统计")
        
        # 用户状态
        if self.current_user:
            user_info = {
                'username': self.current_user['username'],
                'role': self.current_user['role'],
                'last_login': self.current_user.get('last_login', 'N/A')
            }
            self.display.print_stats(user_info, "当前用户")
        else:
            self.display.warning("未登录")
    
    def _handle_user(self, args: Any) -> None:
        """处理用户管理命令"""
        if not self._check_auth():
            return
        
        action = args.user_action
        
        if action == 'create':
            self._create_user(args)
        elif action == 'list':
            self._list_users(args)
        elif action == 'show':
            self._show_user(args)
        else:
            self.display.error(f"未知用户操作: {action}")
    
    def _handle_vulnerability(self, args: Any) -> None:
        """处理漏洞管理命令"""
        if not self._check_auth():
            return
        
        action = args.vuln_action
        
        if action == 'list':
            self._list_vulnerabilities(args)
        elif action == 'add':
            self._add_vulnerability(args)
        elif action == 'search':
            self._search_vulnerabilities(args)
        elif action == 'show':
            self._show_vulnerability(args)
        else:
            self.display.error(f"未知漏洞操作: {action}")
    
    def _handle_target(self, args: Any) -> None:
        """处理目标管理命令"""
        if not self._check_auth():
            return
        
        action = args.target_action
        
        if action == 'list':
            self._list_targets(args)
        elif action == 'add':
            self._add_target(args)
        elif action == 'scan':
            self._scan_target(args)
        else:
            self.display.error(f"未知目标操作: {action}")
    
    def _handle_campaign(self, args: Any) -> None:
        """处理行动计划命令"""
        if not self._check_auth():
            return
        
        action = args.campaign_action
        
        if action == 'list':
            self._list_campaigns(args)
        elif action == 'create':
            self._create_campaign(args)
        else:
            self.display.error(f"未知行动计划操作: {action}")
    
    def _handle_task(self, args: Any) -> None:
        """处理任务管理命令"""
        if not self._check_auth():
            return
        
        action = args.task_action
        
        if action == 'list':
            self._list_tasks(args)
        elif action == 'execute':
            self._execute_task(args)
        else:
            self.display.error(f"未知任务操作: {action}")
    
    def _handle_report(self, args: Any) -> None:
        """处理报告管理命令"""
        if not self._check_auth():
            return
        
        action = args.report_action
        
        if action == 'generate':
            self._generate_report(args)
        elif action == 'list':
            self._list_reports(args)
        else:
            self.display.error(f"未知报告操作: {action}")
    
    def _handle_intelligence(self, args: Any) -> None:
        """处理情报收集命令"""
        if not self._check_auth():
            return
        
        action = args.intel_action
        
        if action == 'collect':
            self._collect_intelligence(args)
        else:
            self.display.error(f"未知情报操作: {action}")
    
    def _handle_maintenance(self, args: Any) -> None:
        """处理系统维护命令"""
        if not self._check_auth() or not self._check_admin():
            return
        
        if args.backup:
            self._backup_database()
        elif args.cleanup:
            self._cleanup_system()
        elif args.stats:
            self._show_system_stats()
        else:
            self.display.error("请指定维护操作")
    
    def _create_user(self, args: Any) -> None:
        """创建用户"""
        if not self._check_admin():
            return
        
        username = args.username
        password = args.password
        
        if not password:
            password = self.display.prompt_input("请输入密码", password=True)
            confirm_password = self.display.prompt_input("请确认密码", password=True)
            if password != confirm_password:
                self.display.error("密码不匹配")
                return
        
        user_id = self.auth.create_user(
            username=username,
            password=password,
            email=args.email or '',
            first_name=getattr(args, 'first_name', '') or '',
            last_name=getattr(args, 'last_name', '') or '',
            role=args.role
        )
        
        if user_id:
            self.display.success(f"用户 {username} 创建成功 (ID: {user_id})")
            self.logger.log_user_action(
                self.current_user['username'], 
                "create_user", 
                f"Created user: {username}"
            )
        else:
            self.display.error("用户创建失败")
    
    def _list_users(self, args: Any) -> None:
        """列出用户"""
        users = self.auth.get_all_users()
        
        if hasattr(args, 'role') and args.role:
            users = [u for u in users if u['role'] == args.role]
        
        self.display.print_user_table(users)
    
    def _show_user(self, args: Any) -> None:
        """显示用户详情"""
        user = None
        
        if args.id:
            user = self.auth.get_user_by_id(args.id)
        elif args.username:
            users = self.auth.get_all_users()
            user = next((u for u in users if u['username'] == args.username), None)
        
        if user:
            self.display.print_stats(user, f"用户详情 - {user['username']}")
        else:
            self.display.error("用户不存在")
    
    def _list_vulnerabilities(self, args: Any) -> None:
        """列出漏洞"""
        filters = {}
        
        if args.severity:
            filters['severity'] = args.severity
        if args.status:
            filters['status'] = args.status
        
        vulnerabilities = self.vuln_manager.list_vulnerabilities(
            filters=filters, 
            limit=args.limit
        )
        
        self.display.print_vulnerability_table(vulnerabilities)
    
    def _add_vulnerability(self, args: Any) -> None:
        """添加漏洞"""
        vuln_data = {
            'title': args.title,
            'cve_id': getattr(args, 'cve_id', None),
            'description': args.description or '',
            'severity': args.severity,
            'cvss_score': getattr(args, 'cvss_score', None),
            'affected_systems': getattr(args, 'affected_systems', '') or ''
        }
        
        vuln_id = self.vuln_manager.create_vulnerability(vuln_data, self.current_user['id'])
        
        if vuln_id:
            self.display.success(f"漏洞创建成功 (ID: {vuln_id})")
        else:
            self.display.error("漏洞创建失败")
    
    def _search_vulnerabilities(self, args: Any) -> None:
        """搜索漏洞"""
        vulnerabilities = self.vuln_manager.search_vulnerabilities(
            args.keyword, 
            limit=args.limit
        )
        
        if vulnerabilities:
            self.display.print_vulnerability_table(vulnerabilities)
        else:
            self.display.warning(f"没有找到包含 '{args.keyword}' 的漏洞")
    
    def _show_vulnerability(self, args: Any) -> None:
        """显示漏洞详情"""
        vuln = self.vuln_manager.get_vulnerability(args.id)
        
        if vuln:
            self.display.print_vulnerability_detail(vuln)
        else:
            self.display.error(f"漏洞 ID {args.id} 不存在")
    
    def _list_targets(self, args: Any) -> None:
        """列出目标"""
        # 这里应该实现目标管理器
        self.display.warning("目标管理功能正在开发中")
    
    def _add_target(self, args: Any) -> None:
        """添加目标"""
        self.display.warning("目标管理功能正在开发中")
    
    def _scan_target(self, args: Any) -> None:
        """扫描目标"""
        self.display.warning("目标扫描功能正在开发中")
    
    def _list_campaigns(self, args: Any) -> None:
        """列出行动计划"""
        self.display.warning("行动计划功能正在开发中")
    
    def _create_campaign(self, args: Any) -> None:
        """创建行动计划"""
        self.display.warning("行动计划功能正在开发中")
    
    def _list_tasks(self, args: Any) -> None:
        """列出任务"""
        self.display.warning("任务管理功能正在开发中")
    
    def _execute_task(self, args: Any) -> None:
        """执行任务"""
        self.display.warning("任务执行功能正在开发中")
    
    def _generate_report(self, args: Any) -> None:
        """生成报告"""
        self.display.warning("报告生成功能正在开发中")
    
    def _list_reports(self, args: Any) -> None:
        """列出报告"""
        self.display.warning("报告管理功能正在开发中")
    
    def _collect_intelligence(self, args: Any) -> None:
        """收集情报"""
        self.display.warning("情报收集功能正在开发中")
    
    def _backup_database(self) -> None:
        """备份数据库"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"data/backups/backup_{timestamp}.db"
        
        if self.database.backup_database(backup_path):
            self.display.success(f"数据库备份成功: {backup_path}")
        else:
            self.display.error("数据库备份失败")
    
    def _cleanup_system(self) -> None:
        """清理系统"""
        # 清理过期会话
        expired_count = self.auth.cleanup_expired_sessions()
        self.display.success(f"清理了 {expired_count} 个过期会话")
    
    def _show_system_stats(self) -> None:
        """显示系统统计"""
        stats = self.database.get_database_stats()
        vuln_stats = self.vuln_manager.get_vulnerability_stats()
        
        all_stats = {**stats, **vuln_stats}
        self.display.print_stats(all_stats, "系统统计信息")
    
    def _check_auth(self) -> bool:
        """检查用户是否已认证"""
        if not self.current_user:
            self.display.error("请先登录")
            return False
        return True
    
    def _check_admin(self) -> bool:
        """检查用户是否为管理员"""
        if not self.current_user or self.current_user.get('role') != 'admin':
            self.display.error("需要管理员权限")
            return False
        return True
    
    def _save_session(self) -> None:
        """保存会话信息"""
        if self.current_token:
            session_file = "data/.session"
            try:
                with open(session_file, 'w') as f:
                    f.write(self.current_token)
            except:
                pass
    
    def _load_session(self) -> None:
        """加载会话信息"""
        session_file = "data/.session"
        try:
            if os.path.exists(session_file):
                with open(session_file, 'r') as f:
                    token = f.read().strip()
                
                user = self.auth.validate_session(token)
                if user:
                    self.current_user = user
                    self.current_token = token
                else:
                    # 会话无效，删除文件
                    os.remove(session_file)
        except:
            pass
    
    def _clear_session(self) -> None:
        """清除会话信息"""
        session_file = "data/.session"
        try:
            if os.path.exists(session_file):
                os.remove(session_file)
        except:
            pass

