"""
NetWatch Alerts Module - Advanced Multi-channel Alerting
Supports: Email, Slack, Discord, Telegram, Webhook, Desktop
"""
import asyncio
import aiohttp
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, List, Optional
from enum import Enum
from dataclasses import dataclass
from datetime import datetime
import json
import os

# Load config from environment
SMTP_CONFIG = {
    "server": os.getenv("SMTP_SERVER", "smtp.gmail.com"),
    "port": int(os.getenv("SMTP_PORT", 587)),
    "username": os.getenv("SMTP_USERNAME", ""),
    "password": os.getenv("SMTP_PASSWORD", "")
}

ALERT_EMAIL = os.getenv("ALERT_EMAIL", "")
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK", "")
DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK", "")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"

class AlertChannel(str, Enum):
    EMAIL = "email"
    SLACK = "slack"
    DISCORD = "discord"
    TELEGRAM = "telegram"
    WEBHOOK = "webhook"
    DESKTOP = "desktop"

@dataclass
class Alert:
    title: str
    message: str
    severity: Severity
    value: float = None
    threshold: float = None
    timestamp: float = None
    channel: AlertChannel = None
    
    def __post_init__(self):
        self.timestamp = self.timestamp or datetime.now().timestamp()
    
    def to_dict(self) -> Dict:
        return {
            "title": self.title,
            "message": self.message,
            "severity": self.severity.value,
            "value": self.value,
            "threshold": self.threshold,
            "timestamp": self.timestamp,
            "datetime": datetime.fromtimestamp(self.timestamp).isoformat()
        }
    
    def get_color(self) -> str:
        colors = {
            Severity.INFO: "#00FF00",
            Severity.WARNING: "#FFFF00", 
            Severity.CRITICAL: "#FFA500",
            Severity.EMERGENCY: "#FF0000"
        }
        return colors.get(self.severity, "#FFFFFF")
    
    def get_emoji(self) -> str:
        emojis = {
            Severity.INFO: "ℹ️",
            Severity.WARNING: "⚠️",
            Severity.CRITICAL: "🔴",
            Severity.EMERGENCY: "🚨"
        }
        return emojis.get(self.severity, "📢")

class AlertEngine:
    """Advanced Alert Engine with multiple channels and retry logic"""
    
    def __init__(self):
        self.alert_history: List[Alert] = []
        self._retry_queue = asyncio.Queue()
        self._running = True
        self.manager = None  # Will be set from main
        
    async def start(self):
        """Start background retry worker"""
        asyncio.create_task(self._retry_worker())
    
    def set_manager(self, manager):
        """Set WebSocket manager reference"""
        self.manager = manager
        print("[AlertEngine] WebSocket manager connected")
    
    async def _retry_worker(self):
        """Retry failed alerts with exponential backoff"""
        while self._running:
            try:
                alert, channel, retry_count = await self._retry_queue.get()
                try:
                    await self._send_to_channel(alert, channel)
                    print(f"[ALERT] Retry successful: {alert.title} on {channel}")
                except Exception as e:
                    if retry_count < 3:
                        backoff = 2 ** retry_count
                        await asyncio.sleep(backoff)
                        await self._retry_queue.put((alert, channel, retry_count + 1))
                    else:
                        print(f"[ALERT] Failed after 3 retries: {alert.title} - {e}")
            except Exception as e:
                print(f"[ALERT] Retry worker error: {e}")
    
    async def send_alert(self, alert: Alert, channels: List[AlertChannel] = None):
        """Send alert to specified channels"""
        if channels is None:
            channels = [AlertChannel.DESKTOP]
        
        self.alert_history.append(alert)
        
        for channel in channels:
            try:
                await self._send_to_channel(alert, channel)
            except Exception as e:
                print(f"[ALERT] Failed to send to {channel.value}: {e}")
                await self._retry_queue.put((alert, channel, 0))
    
    async def _send_to_channel(self, alert: Alert, channel: AlertChannel):
        """Route alert to appropriate channel"""
        if channel == AlertChannel.EMAIL:
            await self._send_email(alert)
        elif channel == AlertChannel.SLACK:
            await self._send_slack(alert)
        elif channel == AlertChannel.DISCORD:
            await self._send_discord(alert)
        elif channel == AlertChannel.TELEGRAM:
            await self._send_telegram(alert)
        elif channel == AlertChannel.WEBHOOK:
            await self._send_webhook(alert)
        elif channel == AlertChannel.DESKTOP:
            await self._send_desktop(alert)
    
    async def _send_email(self, alert: Alert):
        """Send email alert"""
        if not SMTP_CONFIG["username"] or not ALERT_EMAIL:
            # Silent fail - email not configured
            return
        
        try:
            msg = MIMEMultipart()
            msg['From'] = SMTP_CONFIG["username"]
            msg['To'] = ALERT_EMAIL
            msg['Subject'] = f"[NetWatch][{alert.severity.value.upper()}] {alert.title}"
            
            html_body = f"""
            <html>
            <body style="font-family: Arial, sans-serif;">
                <h2 style="color: {alert.get_color()}">{alert.get_emoji()} {alert.severity.value.upper()}: {alert.title}</h2>
                <p><strong>Message:</strong> {alert.message}</p>
                <p><strong>Time:</strong> {datetime.fromtimestamp(alert.timestamp).strftime('%Y-%m-%d %H:%M:%S')}</p>
            """
            if alert.value:
                html_body += f'<p><strong>Value:</strong> {alert.value}'
                if alert.threshold:
                    html_body += f' (Threshold: {alert.threshold})'
                html_body += '</p>'
            
            html_body += """
                <hr>
                <p><small>NetWatch Advanced Monitoring System</small></p>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(html_body, 'html'))
            
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._send_email_sync, msg)
        except Exception as e:
            print(f"[ALERT] Email error: {e}")
    
    def _send_email_sync(self, msg):
        """Synchronous email sending"""
        try:
            with smtplib.SMTP(SMTP_CONFIG["server"], SMTP_CONFIG["port"]) as server:
                server.starttls()
                server.login(SMTP_CONFIG["username"], SMTP_CONFIG["password"])
                server.send_message(msg)
        except Exception as e:
            print(f"[ALERT] Email send error: {e}")
    
    async def _send_slack(self, alert: Alert):
        """Send Slack webhook alert"""
        if not SLACK_WEBHOOK:
            return
        
        try:
            payload = {
                "attachments": [{
                    "color": alert.get_color(),
                    "title": f"{alert.get_emoji()} {alert.title}",
                    "text": alert.message,
                    "fields": [
                        {"title": "Severity", "value": alert.severity.value, "short": True},
                        {"title": "Time", "value": datetime.fromtimestamp(alert.timestamp).strftime('%H:%M:%S'), "short": True}
                    ],
                    "footer": "NetWatch Monitoring",
                    "ts": int(alert.timestamp)
                }]
            }
            
            if alert.value:
                payload["attachments"][0]["fields"].append(
                    {"title": "Value", "value": str(alert.value), "short": True}
                )
            
            async with aiohttp.ClientSession() as session:
                await session.post(SLACK_WEBHOOK, json=payload)
        except Exception as e:
            print(f"[ALERT] Slack error: {e}")
    
    async def _send_discord(self, alert: Alert):
        """Send Discord webhook alert"""
        if not DISCORD_WEBHOOK:
            return
        
        try:
            color_map = {
                Severity.INFO: 0x00FF00,
                Severity.WARNING: 0xFFFF00,
                Severity.CRITICAL: 0xFFA500,
                Severity.EMERGENCY: 0xFF0000
            }
            
            embed = {
                "title": f"{alert.get_emoji()} {alert.title}",
                "description": alert.message,
                "color": color_map.get(alert.severity, 0xFFFFFF),
                "timestamp": datetime.fromtimestamp(alert.timestamp).isoformat(),
                "fields": [
                    {"name": "Severity", "value": alert.severity.value, "inline": True}
                ]
            }
            
            if alert.value:
                embed["fields"].append({"name": "Value", "value": str(alert.value), "inline": True})
            
            async with aiohttp.ClientSession() as session:
                await session.post(DISCORD_WEBHOOK, json={"embeds": [embed]})
        except Exception as e:
            print(f"[ALERT] Discord error: {e}")
    
    async def _send_telegram(self, alert: Alert):
        """Send Telegram message"""
        if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
            return
        
        try:
            emoji_map = {
                Severity.INFO: "ℹ️",
                Severity.WARNING: "⚠️",
                Severity.CRITICAL: "🔴",
                Severity.EMERGENCY: "🚨"
            }
            
            message = f"""{emoji_map[alert.severity]} *[{alert.severity.value.upper()}]* {alert.title}
            
{alert.message}
⏰ {datetime.fromtimestamp(alert.timestamp).strftime('%Y-%m-%d %H:%M:%S')}"""
            
            if alert.value:
                message += f"\n📊 Value: {alert.value}"
                if alert.threshold:
                    message += f" (Threshold: {alert.threshold})"
            
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            async with aiohttp.ClientSession() as session:
                await session.post(url, json={
                    "chat_id": TELEGRAM_CHAT_ID,
                    "text": message,
                    "parse_mode": "Markdown"
                })
        except Exception as e:
            print(f"[ALERT] Telegram error: {e}")
    
    async def _send_webhook(self, alert: Alert):
        """Send to custom webhook"""
        webhook_url = os.getenv("CUSTOM_WEBHOOK", "")
        if not webhook_url:
            return
        
        try:
            async with aiohttp.ClientSession() as session:
                await session.post(webhook_url, json=alert.to_dict())
        except Exception as e:
            print(f"[ALERT] Webhook error: {e}")
    
    async def _send_desktop(self, alert: Alert):
        """Send to connected WebSocket clients (browser notifications)"""
        # Check if manager is available and has active connections
        if self.manager is None:
            # No manager set yet - silently ignore
            return
        
        if not hasattr(self.manager, 'active'):
            return
        
        if not self.manager.active:
            # No active WebSocket clients - silently ignore
            return
        
        try:
            await self.manager.broadcast({
                "type": "alert",
                "data": alert.to_dict()
            })
            print(f"[ALERT] Desktop notification sent: {alert.title}")
        except Exception as e:
            # Silent fail - don't spam console
            pass

# Singleton alert engine
alert_engine = AlertEngine()