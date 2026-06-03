import httpx
from typing import Optional


class TelegramNotifier:
    def __init__(self, bot_token: str = "", chat_id: str = ""):
        self.bot_token = bot_token
        self.chat_id = chat_id

    @property
    def enabled(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    async def send(self, message: str) -> bool:
        if not self.enabled:
            return False
        try:
            async with httpx.AsyncClient() as client:
                r = await client.post(
                    f'https://api.telegram.org/bot{self.bot_token}/sendMessage',
                    json={'chat_id': self.chat_id, 'text': message, 'parse_mode': 'HTML'},
                    timeout=10
                )
                return r.status_code == 200
        except Exception:
            return False

    async def notify_client_over_limit(self, email: str, limit_gb: float, used_gb: float):
        await self.send(f'⚠️ <b>客户端超限</b>\n邮箱: {email}\n已用: {used_gb:.2f} GB / {limit_gb:.2f} GB')

    async def notify_client_expired(self, email: str, expire_date: str):
        await self.send(f'❌ <b>客户端已到期</b>\n邮箱: {email}\n到期日: {expire_date}')

    async def notify_server_high_cpu(self, cpu_percent: float):
        await self.send(f'🔴 <b>CPU 负载过高</b>\n当前: {cpu_percent:.1f}%')

    async def notify_xray_stopped(self):
        await self.send('🔴 <b>Xray 服务已停止</b>')
