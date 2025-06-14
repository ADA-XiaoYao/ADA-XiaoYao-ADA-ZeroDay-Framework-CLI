# ADA-ZeroDay-Framework CLI

> 国家级漏洞武器管理平台 - 命令行版本
> 自动情报 + 持久渗透 + 定点打击

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)

## 📋 项目概述

ADA-ZeroDay-Framework CLI 是一个专为网络安全研究和漏洞管理设计的命令行工具。该框架提供了完整的漏洞生命周期管理解决方案，支持纯命令行操作，无需图形界面。

### 🎯 核心功能

- **🔍 自动情报收集**: 从多种来源自动收集和分析漏洞情报
- **🛡️ 漏洞管理**: 完整的漏洞数据库和分类系统
- **⚡ 漏洞利用**: 集成化的漏洞利用代码管理和测试
- **🎯 目标管理**: 资产发现、扫描和脆弱性评估
- **🚀 持久渗透**: 持久化工具和后门管理系统
- **💥 定点打击**: 精确的攻击链设计和执行控制
- **📊 报告生成**: 自动化的分析报告和行动报告
- **👥 用户管理**: 基于角色的访问控制和权限管理

## 🏗️ 系统架构

```
┌─────────────────────────────────────────────────────────┐
│                    命令行界面 (CLI)                      │
├─────────────────────────────────────────────────────────┤
│                    核心引擎层                            │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐        │
│  │           情报收集引擎       │ │ 渗透测试引擎 │ │ 任务调度系统 │        │
│  └─────────────┘ └─────────────┘ └─────────────┘        │
├─────────────────────────────────────────────────────────┤
│                  数据存储层 (SQLite)                     │
└─────────────────────────────────────────────────────────┘
```

## 📁 项目结构

```
ADA-ZeroDay-Framework-CLI/
├── ada.py                      # 主程序入口
├── requirements.txt            # Python依赖
├── config.yaml                 # 配置文件
├── README.md                   # 项目说明
├── LICENSE                     # 开源许可证
│
├── core/                       # 核心模块
│   ├── __init__.py
│   ├── database.py             # 数据库管理
│   ├── auth.py                 # 认证管理
│   ├── config.py               # 配置管理
│   └── logger.py               # 日志管理
│
├── modules/                    # 功能模块
│   ├── __init__.py
│   ├── vulnerability.py        # 漏洞管理
│   ├── exploit.py              # 漏洞利用
│   ├── target.py               # 目标管理
│   ├── campaign.py             # 行动计划
│   ├── intelligence.py         # 情报收集
│   └── report.py               # 报告生成
│
├── cli/                        # 命令行界面
│   ├── __init__.py
│   ├── commands.py             # 命令定义
│   ├── parser.py               # 参数解析
│   └── display.py              # 显示格式化
│
├── data/                       # 数据目录
│   ├── database.db             # SQLite数据库
│   ├── exploits/               # 漏洞利用代码
│   ├── reports/                # 生成的报告
│   └── logs/                   # 日志文件
│
├── scripts/                    # 工具脚本
│   ├── install.sh              # 安装脚本
│   ├── backup.sh               # 备份脚本
│   └── update.sh               # 更新脚本
│
└── docs/                       # 文档
    ├── installation.md         # 安装指南
    ├── usage.md                # 使用手册
    └── api.md                  # API文档
```

## 🚀 快速开始

### 环境要求

- Python 3.8+
- pip
- Git

### 安装步骤

1. **克隆仓库**
```bash
git clone https://github.com/ADA-XiaoYao/ADA-ZeroDay-Framework-CLI.git
cd ADA-ZeroDay-Framework-CLI
```

2. **安装依赖**
```bash
pip install -r requirements.txt
```

3. **初始化数据库**
```bash
python ada.py init
```

4. **创建管理员用户**
```bash
python ada.py user create --username admin --password admin123 --role admin
```

## 📖 使用指南

### 基本命令

```bash
# 显示帮助信息
python ada.py --help

# 用户登录
python ada.py login --username admin --password admin123

# 查看系统状态
python ada.py status

# 显示所有漏洞
python ada.py vuln list

# 添加新漏洞
python ada.py vuln add --title "CVE-2024-0001" --severity critical

# 搜索漏洞
python ada.py vuln search --keyword "RCE"

# 显示目标列表
python ada.py target list

# 添加目标
python ada.py target add --name "Target Server" --ip 192.168.1.100

# 扫描目标
python ada.py target scan --id 1

# 创建行动计划
python ada.py campaign create --name "Operation Alpha"

# 执行任务
python ada.py task execute --id 1

# 生成报告
python ada.py report generate --type vulnerability --output report.pdf
```

### 高级功能

```bash
# 情报收集
python ada.py intel collect --source cve --days 7

# 漏洞利用测试
python ada.py exploit test --id 1 --target 192.168.1.100

# 批量操作
python ada.py batch --file operations.json

# 数据导入导出
python ada.py export --format json --output data.json
python ada.py import --file data.json

# 系统维护
python ada.py maintenance --backup
python ada.py maintenance --cleanup
```

## 🔧 配置说明

编辑 `config.yaml` 文件进行系统配置：

```yaml
# 数据库配置
database:
  type: sqlite
  path: data/database.db

# 日志配置
logging:
  level: INFO
  file: data/logs/ada.log

# 安全配置
security:
  session_timeout: 3600
  max_login_attempts: 3

# 情报收集配置
intelligence:
  sources:
    - cve
    - exploit-db
    - github
  update_interval: 24

# 报告配置
reports:
  output_dir: data/reports
  template_dir: templates
```

## 🔒 安全特性

- **会话管理**: 基于令牌的会话认证
- **权限控制**: 基于角色的访问控制
- **数据加密**: 敏感数据加密存储
- **审计日志**: 完整的操作审计记录
- **输入验证**: 严格的输入验证和过滤

## 📊 功能模块

### 漏洞管理
- 漏洞信息录入和管理
- CVE数据同步
- 漏洞分类和评级
- 搜索和过滤功能

### 漏洞利用
- 利用代码存储和管理
- 自动化测试框架
- 效果评估和报告
- 代码版本控制

### 目标管理
- 目标资产管理
- 自动化扫描
- 脆弱性分析
- 攻击面评估

### 行动计划
- 行动计划创建和管理
- 任务分配和调度
- 执行状态监控
- 结果统计分析

### 情报收集
- 多源情报收集
- 自动化更新
- 威胁情报分析
- 趋势预测

### 报告生成
- 多格式报告输出
- 自定义报告模板
- 数据可视化
- 自动化生成

## 🛠️ 开发指南

### 添加新模块

1. 在 `modules/` 目录创建新模块文件
2. 在 `cli/commands.py` 中添加命令定义
3. 更新 `cli/parser.py` 中的参数解析
4. 在 `core/database.py` 中添加数据模型

### 代码规范

- 遵循 PEP 8 编码规范
- 使用类型提示
- 添加完整的文档字符串
- 编写单元测试

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## ⚠️ 免责声明

本工具仅用于合法的网络安全研究和教育目的。使用者应当：

- 遵守当地法律法规
- 仅在授权的系统上进行测试
- 不得用于恶意攻击或非法活动
- 承担使用本工具的所有责任

## 📞 联系方式

- 项目维护者: ADA-XiaoYao
- 项目主页: https://github.com/ADA-XiaoYao/ADA-ZeroDay-Framework-CLI

---

**⭐ 如果这个项目对您有帮助，请给我们一个 Star！**python ada.py export --format json --output data.json
python ada.py import --file data.json

# 系统维护
python ada.py maintenance --backup
python ada.py maintenance --cleanup
🔧 配置说明编辑 config.yaml 文件进行系统配置：复制# 数据库配置
database:
  type: sqlite
  path: data/database.db

# 日志配置
logging:
  level: INFO
  file: data/logs/ada.log

# 安全配置
security:
  session_timeout: 3600
  max_login_attempts: 3

# 情报收集配置
intelligence:
  sources:
    - cve
    - exploit-db
    - github
  update_interval: 24

# 报告配置
reports:
  output_dir: data/reports
  template_dir: templates
🔒 安全特性•会话管理: 基于令牌的会话认证•权限控制: 基于角色的访问控制•数据加密: 敏感数据加密存储•审计日志: 完整的操作审计记录•输入验证: 严格的输入验证和过滤📊 功能模块漏洞管理•漏洞信息录入和管理•CVE数据同步•漏洞分类和评级•搜索和过滤功能漏洞利用•利用代码存储和管理•自动化测试框架•效果评估和报告•代码版本控制目标管理•目标资产管理•自动化扫描•脆弱性分析•攻击面评估行动计划•行动计划创建和管理•任务分配和调度•执行状态监控•结果统计分析情报收集•多源情报收集•自动化更新•威胁情报分析•趋势预测报告生成•多格式报告输出•自定义报告模板•数据可视化•自动化生成🛠️ 开发指南添加新模块1.在 modules/ 目录创建新模块文件2.在 cli/commands.py 中添加命令定义3.更新 cli/parser.py 中的参数解析4.在 core/database.py 中添加数据模型代码规范•遵循 PEP 8 编码规范•使用类型提示•添加完整的文档字符串•编写单元测试📄 许可证本项目采用 MIT 许可证 - 查看 LICENSE 文件了解详情。⚠️ 免责声明本工具仅用于合法的网络安全研究和教育目的。使用者应当：•遵守当地法律法规•仅在授权的系统上进行测试•不得用于恶意攻击或非法活动•承担使用本工具的所有责任📞 联系方式•项目维护者: ADA-XiaoYao•项目主页: https://github.com/ADA-XiaoYao/ADA-ZeroDay-Framework-CLI⭐ 如果这个项目对您有帮助，请给我们一个 Star！
