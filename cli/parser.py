"""
命令行参数解析模块
"""

import argparse
from typing import Any

class CLIParser:
    """命令行参数解析器"""
    
    def __init__(self):
        self.parser = self._create_parser()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """创建参数解析器"""
        parser = argparse.ArgumentParser(
            prog='ada',
            description='ADA-ZeroDay-Framework CLI - 国家级漏洞武器管理平台',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
示例用法:
  python ada.py init                                    # 初始化系统
  python ada.py login --username admin                  # 用户登录
  python ada.py vuln list                              # 列出所有漏洞
  python ada.py vuln add --title "CVE-2024-0001"       # 添加漏洞
  python ada.py target scan --id 1                     # 扫描目标
  python ada.py report generate --type vulnerability    # 生成报告
            """
        )
        
        # 全局参数
        parser.add_argument('--version', action='version', version='ADA-ZeroDay-Framework CLI v1.0.0')
        parser.add_argument('--config', help='配置文件路径', default='config.yaml')
        parser.add_argument('--verbose', '-v', action='store_true', help='详细输出')
        parser.add_argument('--quiet', '-q', action='store_true', help='静默模式')
        
        # 子命令
        subparsers = parser.add_subparsers(dest='command', help='可用命令')
        
        # 初始化命令
        init_parser = subparsers.add_parser('init', help='初始化系统')
        init_parser.add_argument('--force', action='store_true', help='强制重新初始化')
        
        # 登录命令
        login_parser = subparsers.add_parser('login', help='用户登录')
        login_parser.add_argument('--username', '-u', required=True, help='用户名')
        login_parser.add_argument('--password', '-p', help='密码')
        
        # 登出命令
        logout_parser = subparsers.add_parser('logout', help='用户登出')
        
        # 状态命令
        status_parser = subparsers.add_parser('status', help='显示系统状态')
        
        # 用户管理命令
        user_parser = subparsers.add_parser('user', help='用户管理')
        user_subparsers = user_parser.add_subparsers(dest='user_action', help='用户操作')
        
        # 用户创建
        user_create_parser = user_subparsers.add_parser('create', help='创建用户')
        user_create_parser.add_argument('--username', '-u', required=True, help='用户名')
        user_create_parser.add_argument('--password', '-p', help='密码')
        user_create_parser.add_argument('--email', '-e', help='邮箱')
        user_create_parser.add_argument('--role', '-r', choices=['user', 'analyst', 'operator', 'admin'], 
                                       default='user', help='用户角色')
        user_create_parser.add_argument('--first-name', help='名')
        user_create_parser.add_argument('--last-name', help='姓')
        
        # 用户列表
        user_list_parser = user_subparsers.add_parser('list', help='列出用户')
        user_list_parser.add_argument('--role', help='按角色过滤')
        
        # 用户详情
        user_show_parser = user_subparsers.add_parser('show', help='显示用户详情')
        user_show_parser.add_argument('--id', type=int, help='用户ID')
        user_show_parser.add_argument('--username', help='用户名')
        
        # 漏洞管理命令
        vuln_parser = subparsers.add_parser('vuln', help='漏洞管理')
        vuln_subparsers = vuln_parser.add_subparsers(dest='vuln_action', help='漏洞操作')
        
        # 漏洞列表
        vuln_list_parser = vuln_subparsers.add_parser('list', help='列出漏洞')
        vuln_list_parser.add_argument('--severity', choices=['low', 'medium', 'high', 'critical'], help='按严重程度过滤')
        vuln_list_parser.add_argument('--status', help='按状态过滤')
        vuln_list_parser.add_argument('--limit', type=int, default=20, help='显示数量限制')
        
        # 漏洞添加
        vuln_add_parser = vuln_subparsers.add_parser('add', help='添加漏洞')
        vuln_add_parser.add_argument('--title', required=True, help='漏洞标题')
        vuln_add_parser.add_argument('--cve-id', help='CVE编号')
        vuln_add_parser.add_argument('--description', help='漏洞描述')
        vuln_add_parser.add_argument('--severity', choices=['low', 'medium', 'high', 'critical'], 
                                    default='medium', help='严重程度')
        vuln_add_parser.add_argument('--cvss-score', type=float, help='CVSS评分')
        vuln_add_parser.add_argument('--affected-systems', help='受影响系统')
        
        # 漏洞搜索
        vuln_search_parser = vuln_subparsers.add_parser('search', help='搜索漏洞')
        vuln_search_parser.add_argument('--keyword', required=True, help='搜索关键词')
        vuln_search_parser.add_argument('--limit', type=int, default=10, help='结果数量限制')
        
        # 漏洞详情
        vuln_show_parser = vuln_subparsers.add_parser('show', help='显示漏洞详情')
        vuln_show_parser.add_argument('--id', type=int, required=True, help='漏洞ID')
        
        # 目标管理命令
        target_parser = subparsers.add_parser('target', help='目标管理')
        target_subparsers = target_parser.add_subparsers(dest='target_action', help='目标操作')
        
        # 目标列表
        target_list_parser = target_subparsers.add_parser('list', help='列出目标')
        target_list_parser.add_argument('--status', help='按状态过滤')
        target_list_parser.add_argument('--priority', help='按优先级过滤')
        
        # 目标添加
        target_add_parser = target_subparsers.add_parser('add', help='添加目标')
        target_add_parser.add_argument('--name', required=True, help='目标名称')
        target_add_parser.add_argument('--ip', help='IP地址')
        target_add_parser.add_argument('--hostname', help='主机名')
        target_add_parser.add_argument('--description', help='描述')
        target_add_parser.add_argument('--priority', choices=['low', 'medium', 'high', 'critical'], 
                                      default='medium', help='优先级')
        
        # 目标扫描
        target_scan_parser = target_subparsers.add_parser('scan', help='扫描目标')
        target_scan_parser.add_argument('--id', type=int, required=True, help='目标ID')
        target_scan_parser.add_argument('--ports', help='端口范围')
        target_scan_parser.add_argument('--timeout', type=int, default=300, help='扫描超时时间')
        
        # 行动计划命令
        campaign_parser = subparsers.add_parser('campaign', help='行动计划管理')
        campaign_subparsers = campaign_parser.add_subparsers(dest='campaign_action', help='行动计划操作')
        
        # 行动计划列表
        campaign_list_parser = campaign_subparsers.add_parser('list', help='列出行动计划')
        campaign_list_parser.add_argument('--status', help='按状态过滤')
        
        # 行动计划创建
        campaign_create_parser = campaign_subparsers.add_parser('create', help='创建行动计划')
        campaign_create_parser.add_argument('--name', required=True, help='计划名称')
        campaign_create_parser.add_argument('--description', help='计划描述')
        campaign_create_parser.add_argument('--objective', help='计划目标')
        campaign_create_parser.add_argument('--priority', choices=['low', 'medium', 'high', 'critical'], 
                                           default='medium', help='优先级')
        
        # 任务管理命令
        task_parser = subparsers.add_parser('task', help='任务管理')
        task_subparsers = task_parser.add_subparsers(dest='task_action', help='任务操作')
        
        # 任务列表
        task_list_parser = task_subparsers.add_parser('list', help='列出任务')
        task_list_parser.add_argument('--status', help='按状态过滤')
        task_list_parser.add_argument('--campaign-id', type=int, help='按行动计划过滤')
        
        # 任务执行
        task_execute_parser = task_subparsers.add_parser('execute', help='执行任务')
        task_execute_parser.add_argument('--id', type=int, required=True, help='任务ID')
        
        # 报告管理命令
        report_parser = subparsers.add_parser('report', help='报告管理')
        report_subparsers = report_parser.add_subparsers(dest='report_action', help='报告操作')
        
        # 报告生成
        report_generate_parser = report_subparsers.add_parser('generate', help='生成报告')
        report_generate_parser.add_argument('--type', required=True, 
                                           choices=['vulnerability', 'target', 'campaign', 'summary'], 
                                           help='报告类型')
        report_generate_parser.add_argument('--format', choices=['pdf', 'html', 'json', 'csv'], 
                                           default='pdf', help='报告格式')
        report_generate_parser.add_argument('--output', help='输出文件路径')
        report_generate_parser.add_argument('--campaign-id', type=int, help='行动计划ID（用于行动计划报告）')
        
        # 报告列表
        report_list_parser = report_subparsers.add_parser('list', help='列出报告')
        report_list_parser.add_argument('--type', help='按类型过滤')
        
        # 情报收集命令
        intel_parser = subparsers.add_parser('intel', help='情报收集')
        intel_subparsers = intel_parser.add_subparsers(dest='intel_action', help='情报操作')
        
        # 情报收集
        intel_collect_parser = intel_subparsers.add_parser('collect', help='收集情报')
        intel_collect_parser.add_argument('--source', choices=['cve', 'exploit-db', 'github', 'all'], 
                                         default='all', help='情报源')
        intel_collect_parser.add_argument('--days', type=int, default=7, help='收集最近几天的情报')
        
        # 系统维护命令
        maintenance_parser = subparsers.add_parser('maintenance', help='系统维护')
        maintenance_parser.add_argument('--backup', action='store_true', help='备份数据库')
        maintenance_parser.add_argument('--cleanup', action='store_true', help='清理过期数据')
        maintenance_parser.add_argument('--stats', action='store_true', help='显示系统统计')
        
        return parser
    
    def parse(self, args=None) -> Any:
        """解析命令行参数"""
        return self.parser.parse_args(args)

