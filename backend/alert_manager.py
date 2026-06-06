"""
ALERT MANAGER - WhatsApp, Telegram, Email Alerts
"""

import os
import time
import aiohttp
import asyncio
import smtplib
from email.mime.text import MIMEText

class AlertManager:
    """Complete alert system with WhatsApp, Telegram, Email, and Desktop notifications"""
    
    def __init__(self):
        # WhatsApp (CallMeBot - free)
        self.whatsapp_phone = os.getenv("WHATSAPP_PHONE", "")
        self.whatsapp_key = os.getenv("WHATSAPP_KEY", "")
        
        # Telegram
        self.telegram_token = os.getenv("TELEGRAM_TOKEN", "")
        self.telegram_chat = os.getenv("TELEGRAM_CHAT", "")
        
        # Email
        self.smtp_user = os.getenv("SMTP_USER", "")
        self.smtp_pass = os.getenv("SMTP_PASS", "")
        self.email_to = os.getenv("EMAIL_TO", "")
        
        self.alert_history = []
    
    async def send_whatsapp(self, title, message, severity="info"):
        """Send WhatsApp alert"""
        if not self.whatsapp_phone or not self.whatsapp_key:
            print(f"[WhatsApp] {title}: {message}")
            return False
        
        emojis = {"critical": "🔴", "warning": "🟡", "info": "🔵"}
        emoji = emojis.get(severity, "📢")
        
        text = f"{emoji} *NetWatch*\n\n*{title}*\n{message}\n\n⏰ {time.strftime('%H:%M:%S')}"
        
        try:
            url = "https://api.callmebot.com/whatsapp.php"
            params = {"phone": self.whatsapp_phone, "text": text, "apikey": self.whatsapp_key}
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, timeout=10) as resp:
                    return resp.status == 200
        except Exception as e:
            print(f"[WhatsApp] Error: {e}")
            return False
    
    async def send_telegram(self, title, message, severity="info"):
        """Send Telegram alert"""
        if not self.telegram_token or not self.telegram_chat:
            print(f"[Telegram] {title}: {message}")
            return False
        
        emojis = {"critical": "🚨", "warning": "⚠️", "info": "ℹ️"}
        emoji = emojis.get(severity, "📢")
        
        text = f"{emoji} *{title}*\n\n{message}"
        
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            params = {"chat_id": self.telegram_chat, "text": text, "parse_mode": "Markdown"}
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, timeout=10) as resp:
                    return resp.status == 200
        except Exception as e:
            print(f"[Telegram] Error: {e}")
            return False
    
    async def send_email(self, title, message, severity="info"):
        """Send email alert"""
        if not self.smtp_user or not self.email_to:
            print(f"[Email] {title}: {message}")
            return False
        
        try:
            msg = MIMEText(f"NetWatch Alert\n\n{title}\n{message}\n\nTime: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            msg['Subject'] = f"[NetWatch] {title}"
            msg['From'] = self.smtp_user
            msg['To'] = self.email_to
            
            with smtplib.SMTP("smtp.gmail.com", 587) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_pass)
                server.send_message(msg)
            return True
        except Exception as e:
            print(f"[Email] Error: {e}")
            return False
    
    async def send_alert(self, title, message, severity="info", channels=None):
        """Send alert to multiple channels"""
        if channels is None:
            channels = ["whatsapp", "telegram"]
        
        results = {}
        
        if "whatsapp" in channels:
            results["whatsapp"] = await self.send_whatsapp(title, message, severity)
        if "telegram" in channels:
            results["telegram"] = await self.send_telegram(title, message, severity)
        if "email" in channels:
            results["email"] = await self.send_email(title, message, severity)
        
        self.alert_history.append({
            'timestamp': time.time(),
            'title': title,
            'message': message,
            'severity': severity,
            'channels': results
        })
        
        return results

alert_manager = AlertManager()