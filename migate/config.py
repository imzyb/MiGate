from pydantic import BaseModel, Field


class ProxyConfig(BaseModel):
    http_host: str = "127.0.0.1"
    http_port: int = 34502
    socks_host: str = "127.0.0.1"
    socks_port: int = 34501


class XrayConfig(BaseModel):
    enabled: bool = True
    bin_path: str = "/usr/local/bin/xray"
    config_path: str = "/etc/migate/xray/config.json"
    api_host: str = "127.0.0.1"
    api_port: int = 10085
    default_outbound_tag: str = "migate-vpngate"
    block_direct_fallback: bool = True


class VPNConfig(BaseModel):
    interface: str = "tun-migate"
    route_table: int = 100
    fwmark: str = "0x66"
    reconnect_interval: int = 30
    max_failures_per_node: int = 3


class EgressConfig(BaseModel):
    backend: str = "openvpn"


class CollectorConfig(BaseModel):
    source: str = "https://www.vpngate.net/api/iphone/"
    refresh_interval: int = 600
    max_nodes: int = 300


class ProbeConfig(BaseModel):
    concurrency: int = 32
    connect_timeout: int = 5
    handshake_timeout: int = 20
    max_latency_ms: int = 500


class SecurityConfig(BaseModel):
    leak_guard: bool = True
    fail_policy: str = "block"
    web_bind: str = "0.0.0.0"
    web_port: int = 8787
    secret_path: str = "auto"


class NotificationConfig(BaseModel):
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""


class MiGateConfig(BaseModel):
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    xray: XrayConfig = Field(default_factory=XrayConfig)
    vpn: VPNConfig = Field(default_factory=VPNConfig)
    egress: EgressConfig = Field(default_factory=EgressConfig)
    collector: CollectorConfig = Field(default_factory=CollectorConfig)
    probe: ProbeConfig = Field(default_factory=ProbeConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    notifications: NotificationConfig = Field(default_factory=NotificationConfig)
