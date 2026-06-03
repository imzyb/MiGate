# MiGate 部署指南

## 系统要求

- **OS**: Ubuntu 20.04+ / Debian 11+ / CentOS 8+
- **Python**: 3.11+
- **内存**: ≥ 512MB
- **磁盘**: ≥ 1GB
- **网络**: 公网 IP（用于代理服务）

## 一键安装

```bash
bash <(curl -Ls https://raw.githubusercontent.com/imzyb/MiGate/main/scripts/install.sh)
```

安装过程：
1. 提示输入面板端口、用户名、密码、路径
2. 安装系统依赖（git, curl, python3, openvpn）
3. 克隆 MiGate 到 `/opt/migate`
4. 创建 Python venv 并安装依赖
5. 运行 `migate setup` 生成配置
6. 创建并启动 systemd 服务
7. 输出 WebUI 地址

## 手动安装

### 1. 克隆仓库

```bash
git clone https://github.com/imzyb/MiGate.git /opt/migate
cd /opt/migate
```

### 2. 创建 venv

```bash
python3.11 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install .
```

### 3. 配置

```bash
mkdir -p /etc/migate

# 生成配置
migate setup \
  --panel-host 0.0.0.0 \
  --panel-port 8787 \
  --admin-user admin \
  --admin-password your-password \
  --base-path /migate \
  --public-host YOUR_PUBLIC_IP \
  --setup-config-target /etc/migate/setup-panel.json \
  --no-dry-run --yes --allow-system-changes
```

### 4. 创建 systemd 服务

```bash
cat > /etc/systemd/system/migate-panel.service << 'EOF'
[Unit]
Description=MiGate Panel
After=network.target

[Service]
Type=simple
ExecStart=/opt/migate/venv/bin/migate panel --host 0.0.0.0 --port 8787 --panel-config /etc/migate/setup-panel.json
WorkingDirectory=/opt/migate
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now migate-panel.service
```

### 5. 验证

```bash
# 检查服务状态
systemctl status migate-panel.service

# 检查端口
ss -ltn | grep 8787

# 测试访问
curl -sS -o /dev/null -w "%{http_code}" http://127.0.0.1:8787/migate/
```

## Nginx 反向代理（推荐）

```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location /migate/ {
        proxy_pass http://127.0.0.1:8787/migate/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # 订阅端点（无需认证）
    location /sub/ {
        proxy_pass http://127.0.0.1:8787/sub/;
    }
}
```

## 升级

```bash
cd /opt/migate
git pull origin main
source venv/bin/activate
pip install --upgrade .
systemctl restart migate-panel.service
```

或使用安装脚本：
```bash
bash <(curl -Ls https://raw.githubusercontent.com/imzyb/MiGate/main/scripts/install.sh) --upgrade
```

## 卸载

```bash
bash <(curl -Ls https://raw.githubusercontent.com/imzyb/MiGate/main/scripts/install.sh) --uninstall
```

卸载内容：
- 停止并禁用 systemd 服务
- 删除服务单元文件
- 删除配置目录 `/etc/migate`
- 删除数据目录 `/var/lib/migate`
- 删除二进制 `/usr/local/bin/migate`
- 删除源码目录 `/opt/migate`

## 故障排查

### 面板无法启动

```bash
# 查看日志
journalctl -u migate-panel.service -n 50 --no-pager

# 检查端口占用
ss -ltn | grep 8787

# 手动启动测试
cd /opt/migate && source venv/bin/activate
migate panel --host 0.0.0.0 --port 8787 --panel-config /etc/migate/setup-panel.json
```

### Xray 无法启动

```bash
# 查看日志
journalctl -u migate-xray.service -n 50 --no-pager

# 检查配置
xray run -config /etc/migate/xray/config.json -test

# 常见问题：端口被占用
ss -ltn | grep 443
```

### 数据库问题

```bash
# 检查数据库
sqlite3 /var/lib/migate/migate.db ".tables"

# 查看入站规则
sqlite3 /var/lib/migate/migate.db "SELECT * FROM inbounds;"

# 查看客户端流量
sqlite3 /var/lib/migate/migate.db "SELECT * FROM client_traffic;"
```

## 配置文件说明

### `/etc/migate/setup-panel.json`

面板配置文件，包含：
- `admin_user` — 管理员用户名
- `password_hash` — 密码 SHA256 哈希
- `base_path` — 面板路径（如 `/migate`）
- `dangerous_actions_enabled` — 是否启用危险操作

### `/etc/migate/xray/config.json`

Xray 配置文件，由面板自动生成和管理。

### `/var/lib/migate/migate.db`

SQLite 数据库，包含：
- `nodes` — 节点配置
- `inbounds` — 入站规则
- `client_traffic` — 客户端流量统计
