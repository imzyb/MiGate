# MiGate

MiGate 是一个 **Go single-binary** 轻量 VPS 面板，使用本地 SQLite 和内嵌 WebUI 管理 Xray 入站与客户端。

当前适合熟悉 VPS/Xray 的用户测试使用。

## 功能

- 单二进制部署，无需 Python/Node 运行环境
- WebUI 管理入站、客户端和基础设置
- 本地 SQLite 数据库
- 生成并应用 Xray 配置
- 支持协议：VLESS、VMess、Trojan、Shadowsocks、Hysteria2
- 支持 systemd 服务管理

## 一键安装

在 Linux VPS 上以 root 执行：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/imzyb/MiGate/main/packaging/install.sh)
```

安装指定版本：

```bash
MIGATE_VERSION=v1.0.0 bash <(curl -Ls https://raw.githubusercontent.com/imzyb/MiGate/main/packaging/install.sh)
```

安装过程中会提示输入：

- 面板端口，默认 `9999`
- 用户名，默认 `admin`
- 密码，留空会自动生成随机密码
- Web 路径，默认 `/panel`
- 是否安装 Xray

安装完成后访问：

```text
http://SERVER_IP:9999/panel
```

## 常用命令

查看状态：

```bash
systemctl status migate
```

重启面板：

```bash
systemctl restart migate
```

查看日志：

```bash
journalctl -u migate -f
```

配置文件：

```text
/etc/migate/panel.json
```

数据库：

```text
/usr/local/migate/migate.db
```

Xray 配置：

```text
/usr/local/migate/xray.json
```

## 说明

MiGate 当前主打单机 VPS 场景，仍在快速迭代。建议先在测试 VPS 上试用，再用于长期服务。
