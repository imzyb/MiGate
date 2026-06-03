# MiGate

MiGate 是一个集成 Xray 代理节点管理的智能面板系统，提供 Web UI 管理、用户流量统计、订阅服务、服务器监控等功能。

## ✨ 核心功能

### 🖥 面板管理
- **节点管理** — 创建/编辑/删除 VLESS/VMess/Trojan/Shadowsocks 入站规则
- **Stream Settings** — 可视化配置 TCP/WS/gRPC/H2 传输层 + TLS/Reality 安全层
- **客户端管理** — 添加/删除客户端，一键生成分享链接
- **X25519 密钥生成** — Reality 协议密钥对在线生成

### 📊 用户流量统计
- **每客户端流量** — 从 xray stats API 实时拉取 `↑上传 ↓下载` 流量
- **流量限制** — 按客户端设置流量上限 (GB)
- **到期时间** — 按客户端设置到期日期
- **自动检测** — 超限/到期客户端自动标记 `❌已超限` / `❌已到期`

### 📡 订阅服务
- **订阅端点** — `GET /sub/{token}` 无需认证
- **格式自动适配** — Clash UA → YAML 配置，其他 → base64 编码链接
- **全协议支持** — VLESS/Trojan/SS + 全部 transport/TLS/Reality 参数

### 📈 服务器监控
- **实时监控** — CPU/RAM/磁盘/运行时间，10 秒自动刷新
- **流量图表** — Chart.js 折线图展示上传/下载趋势
- **颜色编码** — CPU < 70% 绿色，70-90% 黄色，> 90% 红色

### 🔔 Telegram 通知
- **超限告警** — 客户端流量超限时推送通知
- **到期提醒** — 客户端到期时推送通知
- **服务监控** — CPU 过高/Xray 停止时推送通知

### 💾 备份恢复
- **一键备份** — SQLite backup API 创建数据库快照
- **备份列表** — 查看所有备份文件大小和时间
- **一键恢复** — 恢复前自动创建安全备份

### 🔒 安全加固
- **CSRF 防护** — 基于 x-csrf-token header + Origin/Referer 同源检查
- **登录限速** — 5 次/5 分钟滑动窗口，按 IP 独立计数
- **安全头** — X-Content-Type-Options / X-Frame-Options / X-XSS-Protection / Referrer-Policy

### ⚡ 性能优化
- **数据库索引** — remark/enabled/name 复合索引加速查询
- **连接池化** — lazy connection + check_same_thread=False
- **GZip 压缩** — 500B 以上响应自动压缩
- **静态缓存** — Cache-Control: max-age=3600 + ETag

## 🚀 快速开始

### 一键安装

```bash
bash <(curl -Ls https://raw.githubusercontent.com/imzyb/MiGate/main/scripts/install.sh)
```

交互式安装，依次提示：
- 面板端口（默认 8787）
- 管理员用户名（默认 admin）
- 管理员密码
- 自定义路径（默认 /migate）

### 非交互安装

```bash
MIGATE_PANEL_PORT=8787 \
MIGATE_PANEL_USER=admin \
MIGATE_PANEL_PASSWORD='your-password' \
MIGATE_PANEL_BASE_PATH=/migate \
bash <(curl -Ls https://raw.githubusercontent.com/imzyb/MiGate/main/scripts/install.sh)
```

### 访问面板

安装完成后输出：
```
Web UI: http://YOUR_IP:8787/migate/
Username: admin
```

## 📁 项目结构

```
migate/
├── api/
│   └── app.py              # FastAPI 应用（路由 + HTML 渲染）
├── backup/
│   └── manager.py           # 备份管理器
├── client_manager.py        # 客户端 CRUD
├── config.py                # 配置管理
├── database/
│   └── repository.py        # SQLite 数据库（nodes/inbounds/client_traffic）
├── notifications/
│   └── telegram.py          # Telegram Bot 通知
├── panel/
│   └── layout.py            # 面板布局模板 + JS
├── security/
│   ├── csrf.py              # CSRF 中间件
│   ├── headers.py           # 安全头中间件
│   └── rate_limit.py        # 登录限速器
├── system/
│   └── monitor.py           # 系统资源监控（psutil）
├── xray/
│   ├── config_builder.py    # Xray JSON 配置构建
│   ├── links.py             # 分享链接生成
│   ├── node_adapter.py      # NodeRecord → xray config
│   ├── stats.py             # Xray stats API 查询
│   └── validator.py         # Xray 配置校验
└── main.py                  # CLI 入口（typer）
```

## 🔧 CLI 命令

```bash
# 面板
migate panel                          # 启动面板（默认 0.0.0.0:8787）
migate panel --port 8080              # 自定义端口
migate panel --panel-config /etc/migate/panel.json

# Xray
migate xray install                   # 安装 xray
migate xray service save              # 保存 systemd 服务

# 设置
migate setup --no-dry-run --yes --allow-system-changes

# 代理
migate proxy run                      # 启动本地 SOCKS5 代理
migate proxy status                   # 查看代理状态
```

## 📡 API 端点

### 节点管理
- `GET /api/nodes` — 节点列表
- `POST /api/inbounds` — 创建入站
- `POST /api/inbounds/{id}/update` — 更新入站
- `POST /api/inbounds/{id}/delete` — 删除入站
- `POST /api/inbounds/{id}/enable` — 启用入站
- `POST /api/inbounds/{id}/disable` — 禁用入站

### 客户端管理
- `GET /api/inbounds/{id}/clients` — 客户端列表
- `POST /api/inbounds/{id}/clients/add` — 添加客户端
- `POST /api/inbounds/{id}/clients/{client_id}/remove` — 删除客户端
- `POST /api/inbounds/{id}/clients/{email}/limits` — 设置流量限制

### 流量统计
- `GET /api/stats/traffic` — 入站流量统计
- `GET /api/stats/traffic/reset` — 重置流量计数

### 系统监控
- `GET /api/system/resources` — 系统资源（CPU/RAM/磁盘/运行时间）
- `GET /api/system/traffic/history` — 流量历史数据

### 订阅服务
- `GET /sub/{token}` — 订阅端点（自动适配 Clash/base64）

### 备份恢复
- `POST /api/backup/create` — 创建备份
- `GET /api/backup/list` — 备份列表
- `POST /api/backup/restore/{name}` — 恢复备份
- `POST /api/backup/delete/{name}` — 删除备份

### 通知配置
- `GET /api/notifications/telegram/settings` — 获取 Telegram 配置
- `POST /api/notifications/telegram/save` — 保存 Telegram 配置

## 🧪 测试

```bash
# 运行全部测试
pytest tests/ -q

# 运行特定测试
pytest tests/test_panel.py -q
pytest tests/test_security.py -q
pytest tests/test_client_traffic.py -q

# 测试覆盖率
pytest tests/ --tb=short
```

当前测试：**848 全通过**

## 🔐 安全说明

- 面板默认绑定 `0.0.0.0`，生产环境建议通过 nginx 反向代理 + HTTPS
- 登录密码使用 SHA256 哈希存储
- CSRF 防护基于 Origin/Referer 同源检查
- API 端点 (`/api/`, `/sub/`) 不受 CSRF 限制
- 建议使用强密码（≥8 字符）

## 📄 许可证

MIT License
