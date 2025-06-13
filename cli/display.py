"""
显示格式化模块
负责终端输出的美化和格式化
"""

import sys
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm
from rich import box
from datetime import datetime

class Display:
    """显示格式化类"""
    
    def __init__(self):
        self.console = Console()
    
    def success(self, message: str) -> None:
        """显示成功消息"""
        self.console.print(f"✅ {message}", style="bold green")
    
    def error(self, message: str) -> None:
        """显示错误消息"""
        self.console.print(f"❌ {message}", style="bold red")
    
    def warning(self, message: str) -> None:
        """显示警告消息"""
        self.console.print(f"⚠️  {message}", style="bold yellow")
    
    def info(self, message: str) -> None:
        """显示信息消息"""
        self.console.print(f"ℹ️  {message}", style="bold blue")
    
    def print(self, message: str, style: str = None) -> None:
        """普通打印"""
        self.console.print(message, style=style)
    
    def print_panel(self, content: str, title: str = None, style: str = "blue") -> None:
        """显示面板"""
        panel = Panel(content, title=title, border_style=style)
        self.console.print(panel)
    
    def print_header(self, title: str) -> None:
        """显示标题头"""
        self.console.print()
        self.console.rule(f"[bold blue]{title}[/bold blue]")
        self.console.print()
    
    def print_table(self, data: List[Dict[str, Any]], title: str = None, 
                   columns: List[str] = None) -> None:
        """显示表格"""
        if not data:
            self.warning("没有数据可显示")
            return
        
        # 如果没有指定列，使用第一行的键
        if not columns:
            columns = list(data[0].keys())
        
        table = Table(title=title, box=box.ROUNDED)
        
        # 添加列
        for column in columns:
            table.add_column(column.replace('_', ' ').title(), style="cyan")
        
        # 添加行
        for row in data:
            row_data = []
            for column in columns:
                value = row.get(column, '')
                if value is None:
                    value = ''
                elif isinstance(value, bool):
                    value = '✅' if value else '❌'
                elif isinstance(value, list):
                    value = ', '.join(str(v) for v in value)
                row_data.append(str(value))
            table.add_row(*row_data)
        
        self.console.print(table)
    
    def print_vulnerability_table(self, vulnerabilities: List[Dict[str, Any]]) -> None:
        """显示漏洞表格"""
        if not vulnerabilities:
            self.warning("没有找到漏洞")
            return
        
        table = Table(title="漏洞列表", box=box.ROUNDED)
        table.add_column("ID", style="cyan", width=6)
        table.add_column("标题", style="white", width=30)
        table.add_column("CVE编号", style="yellow", width=15)
        table.add_column("严重程度", style="red", width=10)
        table.add_column("状态", style="green", width=10)
        table.add_column("创建时间", style="blue", width=12)
        
        for vuln in vulnerabilities:
            severity_style = self._get_severity_style(vuln.get('severity', 'medium'))
            status_style = self._get_status_style(vuln.get('status', 'new'))
            
            created_at = vuln.get('created_at', '')
            if created_at:
                try:
                    dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    created_at = dt.strftime('%Y-%m-%d')
                except:
                    pass
            
            table.add_row(
                str(vuln.get('id', '')),
                vuln.get('title', '')[:28] + '...' if len(vuln.get('title', '')) > 30 else vuln.get('title', ''),
                vuln.get('cve_id', ''),
                f"[{severity_style}]{vuln.get('severity', 'medium')}[/{severity_style}]",
                f"[{status_style}]{vuln.get('status', 'new')}[/{status_style}]",
                created_at
            )
        
        self.console.print(table)
    
    def print_target_table(self, targets: List[Dict[str, Any]]) -> None:
        """显示目标表格"""
        if not targets:
            self.warning("没有找到目标")
            return
        
        table = Table(title="目标列表", box=box.ROUNDED)
        table.add_column("ID", style="cyan", width=6)
        table.add_column("名称", style="white", width=20)
        table.add_column("IP地址", style="yellow", width=15)
        table.add_column("主机名", style="green", width=20)
        table.add_column("优先级", style="red", width=10)
        table.add_column("状态", style="blue", width=10)
        table.add_column("最后扫描", style="magenta", width=12)
        
        for target in targets:
            priority_style = self._get_priority_style(target.get('priority', 'medium'))
            status_style = self._get_status_style(target.get('status', 'active'))
            
            last_scan = target.get('last_scan', '')
            if last_scan:
                try:
                    dt = datetime.fromisoformat(last_scan.replace('Z', '+00:00'))
                    last_scan = dt.strftime('%Y-%m-%d')
                except:
                    pass
            
            table.add_row(
                str(target.get('id', '')),
                target.get('name', '')[:18] + '...' if len(target.get('name', '')) > 20 else target.get('name', ''),
                target.get('ip_address', ''),
                target.get('hostname', ''),
                f"[{priority_style}]{target.get('priority', 'medium')}[/{priority_style}]",
                f"[{status_style}]{target.get('status', 'active')}[/{status_style}]",
                last_scan
            )
        
        self.console.print(table)
    
    def print_user_table(self, users: List[Dict[str, Any]]) -> None:
        """显示用户表格"""
        if not users:
            self.warning("没有找到用户")
            return
        
        table = Table(title="用户列表", box=box.ROUNDED)
        table.add_column("ID", style="cyan", width=6)
        table.add_column("用户名", style="white", width=15)
        table.add_column("邮箱", style="yellow", width=25)
        table.add_column("角色", style="green", width=10)
        table.add_column("状态", style="blue", width=8)
        table.add_column("最后登录", style="magenta", width=12)
        
        for user in users:
            role_style = self._get_role_style(user.get('role', 'user'))
            status = '✅' if user.get('is_active') else '❌'
            
            last_login = user.get('last_login', '')
            if last_login:
                try:
                    dt = datetime.fromisoformat(last_login.replace('Z', '+00:00'))
                    last_login = dt.strftime('%Y-%m-%d')
                except:
                    pass
            
            table.add_row(
                str(user.get('id', '')),
                user.get('username', ''),
                user.get('email', ''),
                f"[{role_style}]{user.get('role', 'user')}[/{role_style}]",
                status,
                last_login
            )
        
        self.console.print(table)
    
    def print_stats(self, stats: Dict[str, Any], title: str = "系统统计") -> None:
        """显示统计信息"""
        self.print_header(title)
        
        for key, value in stats.items():
            if isinstance(value, dict):
                self.print(f"[bold]{key.replace('_', ' ').title()}:[/bold]")
                for sub_key, sub_value in value.items():
                    self.print(f"  {sub_key}: {sub_value}")
            else:
                self.print(f"[bold]{key.replace('_', ' ').title()}:[/bold] {value}")
    
    def print_vulnerability_detail(self, vuln: Dict[str, Any]) -> None:
        """显示漏洞详情"""
        self.print_header(f"漏洞详情 - {vuln.get('title', 'Unknown')}")
        
        # 基本信息
        basic_info = f"""
[bold]ID:[/bold] {vuln.get('id', 'N/A')}
[bold]标题:[/bold] {vuln.get('title', 'N/A')}
[bold]CVE编号:[/bold] {vuln.get('cve_id', 'N/A')}
[bold]严重程度:[/bold] {self._format_severity(vuln.get('severity', 'medium'))}
[bold]CVSS评分:[/bold] {vuln.get('cvss_score', 'N/A')}
[bold]状态:[/bold] {self._format_status(vuln.get('status', 'new'))}
[bold]受影响系统:[/bold] {vuln.get('affected_systems', 'N/A')}
        """
        
        self.print_panel(basic_info.strip(), "基本信息", "blue")
        
        # 描述
        if vuln.get('description'):
            self.print_panel(vuln['description'], "描述", "green")
        
        # 标签
        if vuln.get('tags'):
            tags = ', '.join(vuln['tags'])
            self.print_panel(tags, "标签", "yellow")
        
        # 时间信息
        time_info = f"""
[bold]发现时间:[/bold] {vuln.get('discovery_date', 'N/A')}
[bold]披露时间:[/bold] {vuln.get('disclosure_date', 'N/A')}
[bold]创建时间:[/bold] {vuln.get('created_at', 'N/A')}
[bold]更新时间:[/bold] {vuln.get('updated_at', 'N/A')}
        """
        
        self.print_panel(time_info.strip(), "时间信息", "cyan")
    
    def _get_severity_style(self, severity: str) -> str:
        """获取严重程度样式"""
        styles = {
            'low': 'green',
            'medium': 'yellow',
            'high': 'red',
            'critical': 'bold red'
        }
        return styles.get(severity.lower(), 'white')
    
    def _get_status_style(self, status: str) -> str:
        """获取状态样式"""
        styles = {
            'new': 'blue',
            'confirmed': 'yellow',
            'in_progress': 'cyan',
            'resolved': 'green',
            'closed': 'dim',
            'active': 'green',
            'inactive': 'red'
        }
        return styles.get(status.lower(), 'white')
    
    def _get_priority_style(self, priority: str) -> str:
        """获取优先级样式"""
        styles = {
            'low': 'green',
            'medium': 'yellow',
            'high': 'red',
            'critical': 'bold red'
        }
        return styles.get(priority.lower(), 'white')
    
    def _get_role_style(self, role: str) -> str:
        """获取角色样式"""
        styles = {
            'user': 'blue',
            'analyst': 'cyan',
            'operator': 'yellow',
            'admin': 'red'
        }
        return styles.get(role.lower(), 'white')
    
    def _format_severity(self, severity: str) -> str:
        """格式化严重程度"""
        style = self._get_severity_style(severity)
        return f"[{style}]{severity.upper()}[/{style}]"
    
    def _format_status(self, status: str) -> str:
        """格式化状态"""
        style = self._get_status_style(status)
        return f"[{style}]{status.upper()}[/{style}]"
    
    def prompt_input(self, message: str, default: str = None, password: bool = False) -> str:
        """提示用户输入"""
        if password:
            return Prompt.ask(message, password=True)
        else:
            return Prompt.ask(message, default=default)
    
    def prompt_confirm(self, message: str, default: bool = False) -> bool:
        """提示用户确认"""
        return Confirm.ask(message, default=default)
    
    def show_progress(self, description: str):
        """显示进度条"""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        )
    
    def clear_screen(self) -> None:
        """清屏"""
        self.console.clear()
    
    def print_separator(self) -> None:
        """打印分隔线"""
        self.console.rule(style="dim")

