# MiGate API 文档

面板地址: `http://YOUR_IP:PORT/BASE_PATH/`

## 认证

### 登录

```
POST /BASE_PATH/auth/login
Content-Type: application/x-www-form-urlencoded

username=admin&password=your-password
```

响应:
- `303` 重定向到面板首页，设置 `migate_session` 和 `migate_csrf` cookie

### 退出

```
POST /BASE_PATH/auth/logout
```

响应: `303` 重定向到登录页

### CSRF 保护

所有面板 POST 请求需要满足以下条件之一:
- 请求来自同源 (Origin/Referer 头匹配面板域名)
- 携带 `x-csrf-token` header，值等于 `migate_csrf` cookie

API 端点 (`/api/`, `/sub/`) 不受 CSRF 限制。

---

## 节点管理

### 创建入站

```
POST /api/inbounds
Content-Type: application/json

{
  "remark": "US-VLESS",
  "protocol": "vless",
  "port": 443,
  "settings": {
    "clients": [
      {
        "id": "uuid-here",
        "email": "user@example.com"
      }
    ]
  },
  "streamSettings": {
    "network": "tcp",
    "security": "tls",
    "tlsSettings": {
      "certMode": "xray-self"
    }
  },
  "tag": "proxy-us"
}
```

支持的协议: `vless`, `vmess`, `trojan`, `shadowsocks`

### 入站列表

```
GET /api/inbounds
```

响应:
```json
[
  {
    "id": 1,
    "remark": "US-VLESS",
    "protocol": "vless",
    "port": 443,
    "enabled": true,
    "settings": { ... },
    "streamSettings": { ... }
  }
]
```

### 更新入站

```
POST /api/inbounds/{id}/update
Content-Type: application/json

{
  "remark": "US-VLESS-Updated",
  "port": 8443,
  "settings": { ... },
  "streamSettings": { ... }
}
```

### 删除入站

```
POST /api/inbounds/{id}/delete
```

### 启用/禁用入站

```
POST /api/inbounds/{id}/enable
POST /api/inbounds/{id}/disable
```

### 节点列表

```
GET /api/nodes
```

返回包含所有入站的节点配置列表。

---

## 客户端管理

### 客户端列表

```
GET /api/inbounds/{id}/clients
```

响应:
```json
[
  {
    "id": "uuid",
    "email": "user@example.com",
    "flow": "xtls-rprx-vision",
    "traffic": {
      "uplink": 1073741824,
      "downlink": 5368709120,
      "total": 10737418240,
      "expiry_time": 1735689600
    },
    "share_link": "vless://uuid@host:443?...",
    "limits": {
      "total_gb": 10,
      "expiry_days": 30
    },
    "status": "active"
  }
]
```

状态说明:
- `active` — 正常
- `exceeded` — 流量超限
- `expired` — 已到期
- `disabled` — 已禁用

### 添加客户端

```
POST /api/inbounds/{id}/clients/add
Content-Type: application/json

{
  "email": "new-user@example.com",
  "id": "auto-generated-uuid",  // 可选
  "flow": "xtls-rprx-vision",   // 可选
  "total_gb": 10,               // 可选，流量限制 GB
  "expiry_days": 30             // 可选，到期天数
}
```

### 删除客户端

```
POST /api/inbounds/{id}/clients/{client_id}/remove
```

### 设置流量限制

```
POST /api/inbounds/{id}/clients/{email}/limits
Content-Type: application/json

{
  "total_gb": 10,      // 0 = 无限制
  "expiry_days": 30    // 0 = 无到期
}
```

---

## 流量统计

### 入站流量统计

```
GET /api/stats/traffic
```

响应:
```json
{
  "inbounds": [
    {
      "tag": "proxy-us",
      "uplink": 1073741824,
      "downlink": 5368709120
    }
  ],
  "total_uplink": 1073741824,
  "total_downlink": 5368709120
}
```

### 重置流量计数

```
POST /api/stats/traffic/reset
```

---

## 订阅服务

### 获取订阅

```
GET /sub/{token}
User-Agent: clash  // 可选，Clash UA 返回 YAML 配置
```

响应:
- Clash UA: `text/yaml` — Clash 配置文件
- 其他 UA: `text/plain` — base64 编码的链接列表

Token 从客户端的 `share_link` 获取。

---

## 系统监控

### 系统资源

```
GET /api/system/resources
```

响应:
```json
{
  "cpu_percent": 25.3,
  "memory": {
    "total": 8589934592,
    "used": 4294967296,
    "percent": 50.0
  },
  "disk": {
    "total": 107374182400,
    "used": 53687091200,
    "percent": 50.0
  },
  "uptime_seconds": 86400
}
```

### 流量历史

```
GET /api/system/traffic/history
```

响应: 最近 1 小时的流量采样数据（30 秒间隔）

---

## 备份恢复

### 创建备份

```
POST /api/backup/create
```

### 备份列表

```
GET /api/backup/list
```

响应:
```json
[
  {
    "name": "backup-2026-06-01-10-30-00.db",
    "size": 1048576,
    "created": "2026-06-01T10:30:00"
  }
]
```

### 恢复备份

```
POST /api/backup/restore/{name}
```

恢复前自动创建安全备份。

### 删除备份

```
POST /api/backup/delete/{name}
```

---

## 通知配置

### 获取 Telegram 配置

```
GET /api/notifications/telegram/settings
```

### 保存 Telegram 配置

```
POST /api/notifications/telegram/save
Content-Type: application/json

{
  "bot_token": "123456:ABC-DEF...",
  "chat_id": "-1001234567890",
  "enabled": true,
  "notify_on_traffic_exceeded": true,
  "notify_on_client_expired": true,
  "notify_on_high_cpu": true,
  "notify_on_xray_down": true
}
```

---

## Stream Settings 配置

### 传输层选项

| 类型 | 说明 | 端口 |
|------|------|------|
| `tcp` | 原始 TCP | 任意 |
| `ws` | WebSocket | 任意 |
| `grpc` | gRPC | 任意 |
| `h2` | HTTP/2 | 任意（需 TLS） |

### TLS 配置

```json
{
  "security": "tls",
  "tlsSettings": {
    "certMode": "xray-self",
    "serverName": "example.com"
  }
}
```

### Reality 配置

```json
{
  "security": "reality",
  "realitySettings": {
    "publicKey": "x25519-public-key",
    "shortId": "short-id",
    "serverName": "www.microsoft.com"
  }
}
```

Public Key 从 `GET /api/x25519` 获取。

---

## 错误码

| 状态码 | 说明 |
|--------|------|
| 200 | 成功 |
| 303 | 重定向（登录/退出） |
| 400 | 请求参数错误 |
| 401 | 未认证 |
| 403 | CSRF 校验失败 |
| 404 | 资源不存在 |
| 422 | 表单字段缺失 |
| 500 | 服务器内部错误 |
