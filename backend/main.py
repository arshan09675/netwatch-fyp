"""
NetWatch FYP - Complete Advanced Network Monitoring System
Version: 7.0.0 (Ultimate Edition)
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, StreamingResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
from typing import List, Dict, Any, Optional
import asyncio
import time
import json
import psutil
import socket
import platform
import threading
from datetime import datetime
from collections import defaultdict

from database import db
from advanced_auth import (
    authenticate_user, generate_token, verify_token,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)
from datetime import timedelta
from alerts import alert_engine, Alert, Severity, AlertChannel
from anomaly_detection import AdvancedAnomalyDetector, TrafficForecaster
from geoip import geoip_service, register_geoip_routes
from packet_sniffer import packet_sniffer, register_sniffer_routes
from threat_intel import threat_intel
from device_manager import device_manager
from arp_spoofer import arp_spoofer
from website_tracker import website_tracker
from alert_manager import alert_manager
from darkweb_detector import darkweb_detector
from auto_blocker import auto_blocker
from ai_predictor import ai_predictor
from advanced_packet_stream import packet_stream

# ============================================
# CONFIGURATION
# ============================================
API_VERSION = "7.0.0"
API_TITLE = "NetWatch Ultimate"

ALERT_THRESHOLD_MBPS = 50
ALERT_THRESHOLD_CPU = 80
ALERT_THRESHOLD_MEM = 85
ALERT_THRESHOLD_PACKETS = 1000
ALERT_THRESHOLD_DDOS = 5000
SNIFFER_AUTO_START = True
DEVICE_SCAN_INTERVAL = 30

_prev_counters: Dict = {}
_prev_time: float = 0.0
_traffic_history: List[dict] = []
_MAX_HISTORY = 300
_packet_rate_history = []
_main_loop = None  # Captured at startup; lets sync callbacks schedule coroutines safely

# collect_metrics() runs every second; persisting per-adapter / per-process /
# prediction rows that often would bloat the DB. Throttle those heavier writes
# to once every _EXTRA_SAVE_INTERVAL seconds.
_EXTRA_SAVE_INTERVAL = 10.0
_last_extra_save = 0.0

anomaly_detector = AdvancedAnomalyDetector(window_size=60, sensitivity=2.5)
forecaster = TrafficForecaster(history_size=60)

# ============================================
# WEBSOCKET MANAGER
# ============================================
class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []
        self.user_agents: Dict[WebSocket, str] = {}
    
    async def connect(self, ws: WebSocket, user_agent: str = "unknown"):
        await ws.accept()
        self.active.append(ws)
        self.user_agents[ws] = user_agent
        print(f"[WebSocket] Client connected. Total: {len(self.active)}")
    
    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)
        if ws in self.user_agents:
            del self.user_agents[ws]
        print(f"[WebSocket] Client disconnected. Total: {len(self.active)}")
    
    async def broadcast(self, data: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(json.dumps(data))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

manager = ConnectionManager()

# ============================================
# FASTAPI APP SETUP
# ============================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _main_loop
    print("=" * 70)
    print(f"🚀 NetWatch v{API_VERSION} Starting...")
    print("=" * 70)

    # Capture the running loop so background threads can schedule coroutines on it.
    _main_loop = asyncio.get_running_loop()
    packet_stream.set_loop(_main_loop)

    alert_engine.set_manager(manager)
    asyncio.create_task(broadcast_loop())
    asyncio.create_task(alert_engine.start())
    asyncio.create_task(cleanup_loop())
    asyncio.create_task(ai_learning_loop())
    
    if SNIFFER_AUTO_START:
        print("[Sniffer] Auto-starting packet capture...")
        try:
            pcap_file = packet_sniffer.start_pcap_capture()
            packet_sniffer.start_sniffing(alert_callback=sniffer_alert_callback)
            if pcap_file:
                print(f"[Sniffer] 📁 Capturing packets to: {pcap_file}")
        except Exception as e:
            print(f"[Sniffer] Error: {e}")
    
    print("[DeviceManager] Starting device discovery...")
    device_manager.start_scanning(interval=DEVICE_SCAN_INTERVAL, alert_callback=sniffer_alert_callback)
    
    print("✅ All services started successfully")
    print("=" * 70)
    yield
    
    print("🛑 NetWatch Shutting down...")
    if packet_sniffer.sniffing:
        packet_sniffer.stop_sniffing()
    device_manager.stop_scanning()
    # Restore ARP for every monitored/blocked device so nobody is left without
    # internet (and no poisoned ARP entries linger) when the server stops.
    try:
        restored = arp_spoofer.stop_all()
        if restored:
            print(f"[ARPSpoofer] Restored on shutdown: {restored}")
    except Exception as e:
        print(f"[ARPSpoofer] Shutdown restore error: {e}")
    print("✅ Shutdown complete")

app = FastAPI(title=API_TITLE, version=API_VERSION, lifespan=lifespan)

# ============================================
# SERVE FRONTEND STATIC FILES
# ============================================

frontend_found = False

if os.path.exists("frontend"):
    app.mount("/frontend", StaticFiles(directory="frontend", html=True), name="frontend")
    app.mount("/Frontend", StaticFiles(directory="frontend", html=True), name="Frontend")
    print("[Static] ✅ Frontend mounted from 'frontend' folder")
    frontend_found = True

if os.path.exists("Frontend"):
    app.mount("/frontend", StaticFiles(directory="Frontend", html=True), name="frontend")
    app.mount("/Frontend", StaticFiles(directory="Frontend", html=True), name="Frontend")
    print("[Static] ✅ Frontend mounted from 'Frontend' folder")
    frontend_found = True

if not frontend_found:
    if os.path.exists("../frontend"):
        app.mount("/frontend", StaticFiles(directory="../frontend", html=True), name="frontend")
        print("[Static] ✅ Frontend mounted from '../frontend'")
    elif os.path.exists("../Frontend"):
        app.mount("/frontend", StaticFiles(directory="../Frontend", html=True), name="frontend")
        print("[Static] ✅ Frontend mounted from '../Frontend'")
    else:
        print("[Static] ⚠️ Frontend folder not found!")

# Middleware
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.add_middleware(GZipMiddleware, minimum_size=1000)

# ============================================
# AUTHENTICATION GATE
# ============================================
# Paths reachable WITHOUT a valid token. Everything else (all /api/*, the
# dashboard page, WebSockets) requires authentication.
_PUBLIC_PATHS = {
    "/", "/login", "/api/auth/login", "/api/health", "/favicon.ico",
}

def _extract_token(request: Request) -> Optional[str]:
    """Pull the JWT from the httponly cookie or an Authorization: Bearer header."""
    tok = request.cookies.get("access_token")
    if tok:
        return tok
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return None

def _token_valid(token: Optional[str]) -> bool:
    """True if the token decodes and is not expired (verify_token returns None otherwise)."""
    return bool(token) and verify_token(token) is not None

@app.middleware("http")
async def auth_gate(request: Request, call_next):
    """Block unauthenticated access. API calls get 401 JSON; page loads
    redirect to /login. WebSockets are gated separately inside their handlers
    (HTTP middleware doesn't see the WebSocket scope)."""
    path = request.url.path

    # Public paths and login assets pass straight through
    if path in _PUBLIC_PATHS:
        return await call_next(request)

    if _token_valid(_extract_token(request)):
        return await call_next(request)

    # Not authenticated
    if path.startswith("/api/") or path.startswith("/ws"):
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)
    # Any HTML/page request → send them to the login screen
    return RedirectResponse(url="/login")

def _ws_authenticated(websocket: WebSocket) -> bool:
    """Validate the JWT cookie sent on a same-origin WebSocket handshake."""
    return _token_valid(websocket.cookies.get("access_token"))

# Register routes
register_geoip_routes(app)
register_sniffer_routes(app)

# ============================================
# HOME PAGE
# ============================================
@app.get("/", response_class=HTMLResponse)
async def home_page():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>NetWatch Ultimate</title>
        <style>
            *{margin:0;padding:0;box-sizing:border-box;}
            body{background:linear-gradient(135deg,#050814 0%,#0a0e27 50%,#11162a 100%);font-family:'Inter',sans-serif;min-height:100vh;color:#fff;}
            .container{max-width:1200px;margin:0 auto;padding:2rem;text-align:center;}
            .logo{font-size:5rem;margin:2rem 0;animation:float 3s infinite;}
            @keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-20px)}}
            h1{font-size:3rem;background:linear-gradient(135deg,#00d4ff,#6c63ff,#f5576c);-webkit-background-clip:text;background-clip:text;color:transparent;}
            .badge{background:rgba(0,212,255,0.2);padding:0.5rem 1rem;border-radius:50px;display:inline-block;margin:1rem;font-size:0.8rem;}
            .features{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1.5rem;margin:3rem 0;}
            .feature-card{background:rgba(17,22,42,0.8);backdrop-filter:blur(10px);border-radius:20px;padding:1.5rem;transition:0.3s;cursor:pointer;text-decoration:none;display:block;}
            .feature-card:hover{transform:translateY(-10px);border-color:#00d4ff;box-shadow:0 20px 40px rgba(0,212,255,0.2);}
            .feature-icon{font-size:2.5rem;}
            .feature-title{font-size:1.2rem;font-weight:600;margin:0.5rem 0;color:#fff;}
            .feature-desc{font-size:0.8rem;color:#7f8cbf;}
            .feature-badge{display:inline-block;background:rgba(0,212,255,0.15);padding:0.2rem 0.6rem;border-radius:20px;font-size:0.65rem;color:#00d4ff;margin-top:0.5rem;}
            .cta-button{display:inline-block;background:linear-gradient(135deg,#00d4ff,#6c63ff);padding:1rem 2rem;border-radius:50px;color:white;text-decoration:none;margin:1rem;font-weight:bold;}
            .footer{margin-top:3rem;color:#4a5580;font-size:0.8rem;}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">🌐</div>
            <h1>NetWatch Ultimate</h1>
            <div class="badge">⚡ AI-Powered Network Monitoring</div>
            <div class="badge">📱 Real-Time Alerts</div>
            <div class="badge">🔮 Dark Web Scanner</div>
            <p style="color:#7f8cbf;margin:1rem;">World's Most Advanced Network Monitoring System</p>
            
            <div class="features">
                <a href="/frontend/dashboard.html" class="feature-card">
                    <div class="feature-icon">📊</div>
                    <div class="feature-title">Real-Time Dashboard</div>
                    <div class="feature-desc">Live network traffic monitoring</div>
                    <div class="feature-badge">✓ Available Now</div>
                </a>
                
                <a href="/frontend/dashboard.html" class="feature-card">
                    <div class="feature-icon">🤖</div>
                    <div class="feature-title">AI Predictions</div>
                    <div class="feature-desc">Next 10 minutes traffic forecast</div>
                    <div class="feature-badge">✓ Active in Dashboard</div>
                </a>
                
                <a href="/frontend/dashboard.html" class="feature-card">
                    <div class="feature-icon">🌐</div>
                    <div class="feature-title">Website Tracker</div>
                    <div class="feature-desc">Live website monitoring</div>
                    <div class="feature-badge">✓ Active in Dashboard</div>
                </a>
                
                <a href="/frontend/dashboard.html" class="feature-card">
                    <div class="feature-icon">📱</div>
                    <div class="feature-title">WhatsApp/Telegram</div>
                    <div class="feature-desc">Instant phone alerts</div>
                    <div class="feature-badge">⚙️ Configure in Settings</div>
                </a>
                
                <a href="/frontend/dashboard.html" class="feature-card">
                    <div class="feature-icon">🔒</div>
                    <div class="feature-title">Auto Block</div>
                    <div class="feature-desc">Automatic threat blocking</div>
                    <div class="feature-badge">✓ Active in Dashboard</div>
                </a>
                
                <a href="/frontend/dashboard.html" class="feature-card">
                    <div class="feature-icon">🌑</div>
                    <div class="feature-title">Dark Web Scanner</div>
                    <div class="feature-desc">Dark web detection</div>
                    <div class="feature-badge">✓ Active in Dashboard</div>
                </a>
            </div>
            
            <a href="/frontend/dashboard.html" class="cta-button">🚀 Launch Dashboard</a>
            <div class="footer">NetWatch v7.0.0 | AI-Powered | Real-Time | Ultimate Edition</div>
        </div>
    </body>
    </html>
    """

# ============================================
# AUTHENTICATION ROUTES
# ============================================

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    """Self-contained login screen (no external assets so it loads pre-auth)."""
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>NetWatch — Login</title>
        <style>
            *{margin:0;padding:0;box-sizing:border-box;font-family:'Inter',system-ui,sans-serif;}
            body{background:linear-gradient(135deg,#050814,#0a0e27 50%,#11162a);min-height:100vh;display:flex;align-items:center;justify-content:center;color:#fff;}
            .card{background:rgba(17,22,42,0.9);backdrop-filter:blur(10px);border:1px solid rgba(0,212,255,0.2);border-radius:20px;padding:2.5rem;width:90%;max-width:380px;box-shadow:0 20px 60px rgba(0,0,0,0.4);}
            .logo{font-size:3rem;text-align:center;margin-bottom:0.5rem;}
            h1{font-size:1.5rem;text-align:center;background:linear-gradient(135deg,#00d4ff,#6c63ff);-webkit-background-clip:text;background-clip:text;color:transparent;margin-bottom:1.5rem;}
            label{display:block;font-size:0.8rem;color:#7f8cbf;margin:0.8rem 0 0.3rem;}
            input{width:100%;padding:0.7rem 0.9rem;border-radius:10px;border:1px solid rgba(108,99,255,0.3);background:rgba(5,8,20,0.6);color:#fff;font-size:0.9rem;}
            input:focus{outline:none;border-color:#00d4ff;}
            button{width:100%;margin-top:1.5rem;padding:0.8rem;border:none;border-radius:10px;background:linear-gradient(135deg,#00d4ff,#6c63ff);color:#fff;font-weight:600;font-size:0.95rem;cursor:pointer;}
            button:hover{opacity:0.9;}
            .err{background:rgba(239,68,68,0.15);border:1px solid rgba(239,68,68,0.4);color:#fca5a5;padding:0.6rem;border-radius:8px;font-size:0.8rem;margin-top:1rem;display:none;}
        </style>
    </head>
    <body>
        <div class="card">
            <div class="logo">🌐</div>
            <h1>NetWatch Login</h1>
            <form id="f">
                <label>Username</label>
                <input id="u" autocomplete="username" autofocus required>
                <label>Password</label>
                <input id="p" type="password" autocomplete="current-password" required>
                <button type="submit">Sign In</button>
                <div class="err" id="e"></div>
            </form>
        </div>
        <script>
            const f=document.getElementById('f'), e=document.getElementById('e');
            f.addEventListener('submit', async (ev)=>{
                ev.preventDefault();
                e.style.display='none';
                try{
                    const r=await fetch('/api/auth/login',{
                        method:'POST',
                        headers:{'Content-Type':'application/json'},
                        body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})
                    });
                    const d=await r.json();
                    if(r.ok && d.success){ window.location.href='/frontend/dashboard.html'; }
                    else { e.textContent=d.error||'Login failed'; e.style.display='block'; }
                }catch(err){ e.textContent='Connection error'; e.style.display='block'; }
            });
        </script>
    </body>
    </html>
    """

@app.post("/api/auth/login")
async def auth_login(request: Request):
    """Validate credentials, issue a JWT, and set it as an httponly cookie so
    same-origin fetches and the WebSocket handshake carry it automatically."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    ip = request.client.host if request.client else "unknown"

    result = authenticate_user(username, password, ip)
    if not result.get("success"):
        return JSONResponse(
            {"success": False, "error": result.get("error", "Invalid credentials")},
            status_code=401
        )

    token = generate_token(
        {"sub": result["user_id"], "role": result["role"], "username": result["username"]},
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    resp = JSONResponse({
        "success": True,
        "username": result["username"],
        "role": result["role"],
        "token": token,   # also returned for non-browser/API clients
    })
    resp.set_cookie(
        "access_token", token,
        httponly=True, samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    return resp

@app.post("/api/auth/logout")
async def auth_logout():
    resp = JSONResponse({"success": True})
    resp.delete_cookie("access_token")
    return resp

@app.get("/api/auth/me")
async def auth_me(request: Request):
    """Return the current user from the token (used by the dashboard if needed)."""
    payload = verify_token(_extract_token(request))
    if not payload:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)
    return {"user_id": payload.get("sub"), "username": payload.get("username"),
            "role": payload.get("role")}

# ============================================
# ADVANCED FEATURES API ROUTES
# ============================================

@app.get("/api/websites")
async def get_websites():
    connections = get_live_connections(150)
    stats = website_tracker.update_from_connections(connections)
    return stats

@app.get("/api/ai/predict")
async def ai_predict():
    metrics = await collect_metrics()
    current = metrics.get('total_mbps', 0)
    ai_predictor.add_data(current)
    return {
        'predictions': ai_predictor.predict(10),
        'insights': ai_predictor.get_insights(),
        'current': current
    }

@app.get("/api/darkweb/scan")
async def scan_darkweb(ip: str, port: int = 0):
    result = darkweb_detector.scan(ip, port)
    if result['is_darkweb'] or result['is_malicious']:
        darkweb_detector.add_detection(result)
        await alert_manager.send_alert(
            "Dark Web Detected",
            f"Connection to {ip}:{port} - {result['reason']}",
            "critical"
        )
    return result

# ============================================
# THREAT STATUS ENDPOINT - FIXED WITH ABUSEIPDB CONFIGURED FLAG
# ============================================

@app.get("/api/threats/status")
async def get_threats_status():
    return {
        'blocked': list(auto_blocker.blocked_ips),
        'total': len(auto_blocker.blocked_ips),
        'enabled': auto_blocker.enabled,
        'abuseipdb_configured': bool(auto_blocker.abuseipdb_key)
    }

@app.post("/api/threats/block/{ip}")
async def block_ip(ip: str, reason: str = "Manual block"):
    result = auto_blocker.block(ip, reason)
    return {'success': result}

@app.post("/api/threats/unblock/{ip}")
async def unblock_ip(ip: str):
    result = auto_blocker.unblock(ip)
    return {'success': result}

@app.post("/api/alerts/test")
async def test_alerts():
    results = await alert_manager.send_alert(
        "Test Alert",
        "This is a test message from NetWatch",
        "info",
        ["whatsapp", "telegram", "email"]
    )
    return results

@app.get("/api/darkweb/detections")
async def get_darkweb_detections(limit: int = 50):
    return darkweb_detector.get_recent(limit)

# ============================================
# PACKET STREAM API ROUTES
# ============================================

@app.websocket("/ws/packets")
async def packet_websocket(websocket: WebSocket):
    if not _ws_authenticated(websocket):
        await websocket.close(code=1008)   # policy violation
        return
    await websocket.accept()
    await packet_stream.subscribe(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)
            
            if msg.get('type') == 'filter':
                packet_stream.set_filter(msg.get('filter_type'), msg.get('values', []))
                await websocket.send_text(json.dumps({
                    'type': 'filter_applied',
                    'filters': packet_stream.filters
                }))
            
            elif msg.get('type') == 'get_stats':
                await websocket.send_text(json.dumps({
                    'type': 'stats',
                    'data': packet_stream.get_stats()
                }))
            
            elif msg.get('type') == 'get_packets':
                packets = packet_stream.get_packets(msg.get('limit', 100), msg.get('offset', 0))
                await websocket.send_text(json.dumps({
                    'type': 'packets',
                    'data': packets,
                    'total': len(packet_stream.packets)
                }))
            
            elif msg.get('type') == 'clear':
                packet_stream.clear_stats()
                await websocket.send_text(json.dumps({
                    'type': 'cleared'
                }))
    
    except WebSocketDisconnect:
        packet_stream.unsubscribe(websocket)

@app.get("/api/packets/export/pcap")
async def export_pcap():
    pcap_data = packet_stream.export_pcap()
    return StreamingResponse(
        iter([pcap_data]),
        media_type="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": f"attachment; filename=netwatch_capture_{int(time.time())}.pcap"}
    )

@app.get("/api/packets/stats")
async def get_packet_stats():
    return packet_stream.get_stats()

@app.get("/api/packets/list")
async def get_packets(limit: int = 100, offset: int = 0):
    return {
        'packets': packet_stream.get_packets(limit, offset),
        'total': len(packet_stream.packets),
        'stats': packet_stream.get_stats()
    }

@app.post("/api/packets/filter")
async def set_packet_filter(filter_type: str, values: List[str] = []):
    packet_stream.set_filter(filter_type, values)
    return {'filters': packet_stream.filters}

@app.post("/api/packets/clear")
async def clear_packets():
    packet_stream.clear_stats()
    return {'cleared': True}

# ============================================
# EXISTING API ROUTES
# ============================================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    if not _ws_authenticated(websocket):
        await websocket.close(code=1008)   # policy violation
        return
    await manager.connect(websocket, "")
    try:
        initial_data = await collect_metrics()
        await websocket.send_text(json.dumps(initial_data))
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/api/metrics")
async def get_metrics():
    return await collect_metrics()

@app.get("/api/dashboard")
async def get_dashboard():
    metrics = await collect_metrics()
    return {
        "metrics": metrics,
        "alerts": db.get_alerts(limit=20, acknowledged=False),
        "devices": device_manager.get_stats(),
        "threats": threat_intel.get_threat_stats(),
        "websites": website_tracker.get_stats()
    }

@app.get("/api/alerts")
async def get_alerts(limit: int = 100, acknowledged: bool = None):
    return db.get_alerts(limit=limit, acknowledged=acknowledged)

@app.post("/api/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: int):
    db.acknowledge_alert(alert_id)
    return {"status": "acknowledged"}

@app.get("/api/connections")
async def live_connections(limit: int = 30):
    return get_live_connections(limit)

@app.get("/api/devices")
async def get_devices():
    return device_manager.get_device_list()

@app.get("/api/devices/stats")
async def get_device_stats():
    return device_manager.get_stats()

@app.post("/api/devices/rescan")
async def rescan_devices():
    """Trigger an immediate device scan in the background and return current list."""
    def _run():
        discovered, active_ips = device_manager.scan_all_networks()
        device_manager.update_devices(discovered, active_ips)
    threading.Thread(target=_run, daemon=True).start()
    return {"status": "scan started", "networks": device_manager.networks_to_scan}

# ============================================
# ARP SPOOFER / MITM MONITORING ROUTES
# ============================================

@app.get("/api/spoof/status")
async def spoof_status():
    # get_status() does a cheap, throttled live re-detect (socket + route print),
    # so run it off the event loop to avoid blocking other requests.
    return await asyncio.to_thread(arp_spoofer.get_status)

@app.post("/api/spoof/start/{target_ip}")
async def spoof_start(target_ip: str):
    """Start monitoring a single device (ARP spoof + capture).

    Runs the (blocking) spoof setup in a worker thread but WAITS for and
    RETURNS the real result, so the UI knows whether monitoring actually began
    — or exactly why it failed (gateway/hotspot host, device offline, wrong
    network, no Npcap, …). Previously this fired-and-forgot the call and always
    reported success, which is why the button never flipped and no traffic
    card appeared when the spoof silently failed.
    """
    result = await asyncio.to_thread(arp_spoofer.start_spoof, target_ip)
    print(f"[API] /spoof/start {target_ip} -> {result}")
    return JSONResponse(result, status_code=200 if result.get("ok") else 400)

@app.post("/api/spoof/stop/{target_ip}")
async def spoof_stop(target_ip: str):
    """Stop monitoring one device and restore its ARP entries. Returns the real
    result so the UI can confirm the stop (or surface an error)."""
    result = await asyncio.to_thread(arp_spoofer.stop_spoof, target_ip)
    print(f"[API] /spoof/stop {target_ip} -> {result}")
    return JSONResponse(result, status_code=200 if result.get("ok") else 400)

@app.post("/api/spoof/start-all")
async def spoof_start_all():
    """Spoof every currently-discovered device (staggered)."""
    targets = [d["ip"] for d in device_manager.get_device_list() if d.get("online")]
    def _run():
        arp_spoofer.start_all(targets)
    threading.Thread(target=_run, daemon=True).start()
    return {"status": "starting", "targets": targets}

@app.post("/api/spoof/stop-all")
async def spoof_stop_all():
    """EMERGENCY STOP — restore ARP for all monitored devices immediately."""
    results = arp_spoofer.stop_all()
    return {"status": "stopped", "results": results}

@app.get("/api/spoof/traffic")
async def spoof_traffic_all():
    return arp_spoofer.get_traffic()

@app.get("/api/spoof/traffic/{target_ip}")
async def spoof_traffic_one(target_ip: str):
    return arp_spoofer.get_traffic(target_ip)

# ============================================
# BLOCK / UNBLOCK ROUTES (cut a device's internet)
# ============================================
# Same ARP-spoof mechanism as monitoring, but a blocked device's packets are
# NOT forwarded — they arrive at this PC and are dropped, cutting its internet.
# Unblock restores the correct ARP entries so the device comes back online.

@app.post("/api/block/start/{target_ip}")
async def block_start(target_ip: str):
    """Block one device: ARP-spoof it and drop (don't forward) its packets."""
    result = await asyncio.to_thread(arp_spoofer.block_device, target_ip)
    print(f"[API] /block/start {target_ip} -> {result}")
    return JSONResponse(result, status_code=200 if result.get("ok") else 400)

@app.post("/api/block/stop/{target_ip}")
async def block_stop(target_ip: str):
    """Unblock one device: stop the spoof and restore its ARP → internet back."""
    result = await asyncio.to_thread(arp_spoofer.unblock_device, target_ip)
    print(f"[API] /block/stop {target_ip} -> {result}")
    return JSONResponse(result, status_code=200 if result.get("ok") else 400)

@app.post("/api/block/stop-all")
async def block_stop_all():
    """Unblock ALL currently-blocked devices (restore everyone's internet)."""
    results = await asyncio.to_thread(arp_spoofer.unblock_all)
    print(f"[API] /block/stop-all -> {results}")
    return {"status": "unblocked", "results": results}

@app.get("/api/block/status")
async def block_status():
    """Which devices are currently blocked (plus live gateway/subnet)."""
    return await asyncio.to_thread(arp_spoofer.get_block_status)

@app.get("/api/threat/stats")
async def threat_stats():
    return threat_intel.get_threat_stats()

@app.get("/api/threat/check/{ip}")
async def check_ip_threat(ip: str):
    result = await threat_intel.check_ip_reputation(ip)
    return {"ip": result.ip, "is_malicious": result.is_malicious, "threat_score": result.threat_score, "category": result.category}

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "version": API_VERSION, "ws_clients": len(manager.active)}

@app.get("/api/export/csv")
async def export_csv(hours: int = 24):
    import csv, io
    data = db.get_traffic_history(hours=hours)
    output = io.StringIO()
    if data:
        writer = csv.DictWriter(output, fieldnames=list(data[0].keys()))
        writer.writeheader()
        writer.writerows(data)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=netwatch_{int(time.time())}.csv"})

# ============================================
# HELPER FUNCTIONS
# ============================================

async def ai_learning_loop():
    print("[AI] Learning loop started")
    while True:
        try:
            metrics = await collect_metrics()
            current = metrics.get('total_mbps', 0)
            ai_predictor.add_data(current)
        except Exception as e:
            print(f"[AI] Learning error: {e}")
        await asyncio.sleep(5)

def get_ipv4(iface: str):
    for a in psutil.net_if_addrs().get(iface, []):
        if a.family == socket.AF_INET:
            return a.address
    return None

def bps_to_mbps(b: float) -> float:
    return round(b * 8 / 1_000_000, 3)

def get_top_processes(limit: int = 10):
    process_bandwidth = defaultdict(float)
    try:
        io_1 = {}
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                io = proc.io_counters()
                if io:
                    io_1[proc.info['pid']] = {'name': proc.info['name'], 'read': io.read_bytes, 'write': io.write_bytes}
            except: pass
        time.sleep(0.5)
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                if pid in io_1:
                    io = proc.io_counters()
                    if io:
                        read_rate = (io.read_bytes - io_1[pid]['read']) / 0.5
                        write_rate = (io.write_bytes - io_1[pid]['write']) / 0.5
                        total_mbps = (read_rate + write_rate) * 8 / 1_000_000
                        if total_mbps > 0.01:
                            process_bandwidth[io_1[pid]['name']] += total_mbps
            except: pass
    except: pass
    sorted_procs = sorted(process_bandwidth.items(), key=lambda x: x[1], reverse=True)
    return [{"name": name, "mbps": round(mbps, 2)} for name, mbps in sorted_procs[:limit]]

def get_live_connections(limit: int = 30):
    connections = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED':
                proc_name = ""
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name()
                    except: proc_name = "unknown"
                connections.append({
                    "local_ip": conn.laddr.ip if conn.laddr else "",
                    "local_port": conn.laddr.port if conn.laddr else "",
                    "remote_ip": conn.raddr.ip if conn.raddr else "",
                    "remote_port": conn.raddr.port if conn.raddr else "",
                    "process": proc_name
                })
            if len(connections) >= limit: break
    except: pass
    return connections

def get_system_stats():
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    uptime = time.time() - psutil.boot_time()
    return {
        "cpu_pct": psutil.cpu_percent(interval=None),
        "mem_pct": mem.percent,
        "mem_used_gb": round(mem.used / 1e9, 2),
        "mem_total_gb": round(mem.total / 1e9, 2),
        "disk_pct": disk.percent,
        "disk_used_gb": round(disk.used / 1e9, 2),
        "disk_total_gb": round(disk.total / 1e9, 2),
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "uptime_hrs": round(uptime / 3600, 2),
    }

async def collect_metrics():
    global _prev_counters, _prev_time, _traffic_history
    
    now = time.time()
    counters = psutil.net_io_counters(pernic=True)
    stats = psutil.net_if_stats()
    dt = max(now - _prev_time, 0.001) if _prev_time else 1.0
    
    adapters = []
    total_recv_bps = 0
    total_sent_bps = 0
    
    for name, cur in counters.items():
        prev = _prev_counters.get(name)
        bps_recv = bps_sent = 0
        pps_recv = pps_sent = 0
        if prev:
            bps_recv = max(0, cur.bytes_recv - prev.bytes_recv) / dt
            bps_sent = max(0, cur.bytes_sent - prev.bytes_sent) / dt
            pps_recv = max(0, cur.packets_recv - prev.packets_recv) / dt
            pps_sent = max(0, cur.packets_sent - prev.packets_sent) / dt
        total_recv_bps += bps_recv
        total_sent_bps += bps_sent
        iface = stats.get(name)
        adapters.append({
            "name": name, "is_up": iface.isup if iface else False,
            "speed_mbps": iface.speed if iface else 0, "ipv4": get_ipv4(name),
            "mbps_sent": bps_to_mbps(bps_sent), "mbps_recv": bps_to_mbps(bps_recv),
            "packets_sent_ps": round(pps_sent, 1), "packets_recv_ps": round(pps_recv, 1),
            "errors_in": cur.errin, "errors_out": cur.errout,
            "drops_in": cur.dropin, "drops_out": cur.dropout,
            "bytes_recv": cur.bytes_recv, "bytes_sent": cur.bytes_sent
        })
    
    _prev_counters = counters
    _prev_time = now
    
    total_recv_mbps = bps_to_mbps(total_recv_bps)
    total_sent_mbps = bps_to_mbps(total_sent_bps)
    total_mbps = round(total_recv_mbps + total_sent_mbps, 3)
    
    ts_str = datetime.utcfromtimestamp(now).strftime('%H:%M:%S')
    _traffic_history.append({"timestamp": now, "time_str": ts_str, "mbps_recv": total_recv_mbps, "mbps_sent": total_sent_mbps, "total_mbps": total_mbps})
    if len(_traffic_history) > _MAX_HISTORY:
        _traffic_history.pop(0)
    
    packet_rate = packet_sniffer.get_stats().get("packets_per_second", 0) if packet_sniffer.sniffing else 0
    _packet_rate_history.append(packet_rate)
    if len(_packet_rate_history) > 10:
        _packet_rate_history.pop(0)
    
    if packet_rate > ALERT_THRESHOLD_DDOS:
        await alert_engine.send_alert(Alert(title="🚨 DDoS Attack Detected!", message=f"Packet rate: {packet_rate:.0f} pps", severity=Severity.CRITICAL, value=packet_rate), channels=[AlertChannel.DESKTOP])
        db.save_alert(alert_type="ddos", severity="critical", title="DDoS Attack Detected", message=f"Packet rate: {packet_rate:.0f} pps", value=packet_rate)
        await alert_manager.send_alert("DDoS Attack Detected", f"Packet rate: {packet_rate:.0f} pps", "critical")
    
    anomaly_result = anomaly_detector.detect(total_mbps, now)
    if anomaly_result.is_anomaly:
        await alert_engine.send_alert(Alert(title="🚨 Traffic Anomaly Detected", message=anomaly_result.message, severity=Severity.CRITICAL, value=total_mbps), channels=[AlertChannel.DESKTOP])
        db.save_alert(alert_type="anomaly", severity=anomaly_result.severity, title="Traffic Anomaly", message=anomaly_result.message, value=total_mbps)
    
    system_stats = get_system_stats()
    if total_mbps > ALERT_THRESHOLD_MBPS:
        await alert_engine.send_alert(Alert(title="⚠️ Bandwidth Exceeded", message=f"{total_mbps:.2f} Mbps", severity=Severity.WARNING, value=total_mbps), channels=[AlertChannel.DESKTOP])
    if system_stats["cpu_pct"] > ALERT_THRESHOLD_CPU:
        await alert_engine.send_alert(Alert(title="🔥 High CPU", message=f"{system_stats['cpu_pct']:.1f}%", severity=Severity.WARNING, value=system_stats["cpu_pct"]), channels=[AlertChannel.DESKTOP])
    if system_stats["mem_pct"] > ALERT_THRESHOLD_MEM:
        await alert_engine.send_alert(Alert(title="💾 High Memory", message=f"{system_stats['mem_pct']:.1f}%", severity=Severity.WARNING, value=system_stats["mem_pct"]), channels=[AlertChannel.DESKTOP])
    
    forecaster.add_value(total_mbps)
    next_pred, confidence = forecaster.predict_next()
    
    ai_predictor.add_data(total_mbps)
    connections = get_live_connections(100)
    websites_stats = website_tracker.update_from_connections(connections)
    
    malicious_connections = []
    for conn in get_live_connections(50):
        remote_ip = conn.get("remote_ip", "")
        if remote_ip and not remote_ip.startswith(('192.168.', '10.', '172.', '127.', '169.254.')):
            threat = await threat_intel.check_ip_reputation(remote_ip)
            if threat and threat.is_malicious:
                malicious_connections.append({"ip": remote_ip, "threat_score": threat.threat_score, "category": threat.category})
                await alert_engine.send_alert(Alert(title=f"⚠️ Malicious IP!", message=f"{remote_ip} - {threat.category}", severity=Severity.CRITICAL, value=threat.threat_score), channels=[AlertChannel.DESKTOP])
                auto_blocker.report_threat(remote_ip, threat.threat_score, threat.category)
    
    payload = {
        "type": "metrics", "timestamp": now, "time_str": ts_str,
        "total_mbps_recv": total_recv_mbps, "total_mbps_sent": total_sent_mbps, "total_mbps": total_mbps,
        "packet_rate_pps": packet_rate, "adapters": adapters, "system": system_stats,
        "traffic_history": _traffic_history[-60:], "top_processes": get_top_processes(),
        "live_connections": get_live_connections(15), "malicious_connections": malicious_connections,
        "prediction": {"next_mbps": next_pred, "confidence": confidence},
        "anomaly": {"is_anomaly": anomaly_result.is_anomaly, "severity": anomaly_result.severity},
        "websites": websites_stats,
        "sniffer": packet_sniffer.get_stats() if packet_sniffer.sniffing else {"active": False},
        "ws_clients": len(manager.active)
    }
    
    db.save_traffic(payload)

    # ── persist the previously-unused tables (throttled) ────────────────────
    # adapter_traffic, process_history, predictions, daily_summary were all
    # defined but never written to. Wire them up here off the metrics loop.
    global _last_extra_save
    if now - _last_extra_save >= _EXTRA_SAVE_INTERVAL:
        _last_extra_save = now
        try:
            # 1. Per-adapter traffic — one row per active adapter
            for ad in adapters:
                if ad.get("is_up"):
                    db.save_adapter_traffic(now, ad)

            # 2. Top processes by bandwidth — one row each
            for proc in payload["top_processes"]:
                db.save_process_history(now, proc["name"], proc["mbps"])

            # 3. ML prediction for later accuracy comparison
            if next_pred is not None:
                db.save_prediction(
                    predicted_time=now + 60,      # forecast is ~1 min ahead
                    predicted_mbps=float(next_pred),
                    confidence=float(confidence),
                    actual_mbps=None
                )

            # 4. Daily usage rollup (recv/sent GB accrued over this interval)
            interval_hr = _EXTRA_SAVE_INTERVAL / 3600.0
            recv_gb = total_recv_mbps / 8.0 * interval_hr * 3600.0 / 1000.0
            sent_gb = total_sent_mbps / 8.0 * interval_hr * 3600.0 / 1000.0
            db.update_daily_usage(datetime.now().strftime('%Y-%m-%d'), recv_gb, sent_gb)
        except Exception as exc:
            print(f"[Metrics] Extra-table save error: {exc}")

    return payload

async def broadcast_loop():
    print("[Broadcaster] Started")
    await asyncio.sleep(1)
    while True:
        try:
            payload = await collect_metrics()
            if manager.active:
                await manager.broadcast(payload)
        except Exception as e:
            print(f"[Broadcaster] Error: {e}")
        await asyncio.sleep(1)

async def cleanup_loop():
    while True:
        await asyncio.sleep(86400)
        db.cleanup_old_data(days=30)

def sniffer_alert_callback(title: str, message: str, severity: str, value: float):
    # Called from device_manager's scan thread and the Scapy sniffer thread —
    # asyncio.create_task() requires the event loop's own thread, so it raises here.
    # run_coroutine_threadsafe() is the correct cross-thread call.
    severity_map = {"info": Severity.INFO, "warning": Severity.WARNING, "critical": Severity.CRITICAL}
    if _main_loop and _main_loop.is_running():
        asyncio.run_coroutine_threadsafe(
            alert_engine.send_alert(
                Alert(title=title, message=message,
                      severity=severity_map.get(severity, Severity.WARNING), value=value),
                channels=[AlertChannel.DESKTOP]
            ),
            _main_loop
        )
    db.save_alert(alert_type="security", severity=severity, title=title, message=message, value=value)
    if severity == "critical" and _main_loop and _main_loop.is_running():
        asyncio.run_coroutine_threadsafe(
            alert_manager.send_alert(title, message, severity),
            _main_loop
        )

if __name__ == "__main__":
    import uvicorn
    print("""
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║     ███╗   ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗   ║
    ║     ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║   ║
    ║     ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║   ║
    ║     ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║   ║
    ║     ██║ ╚████║███████╗   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║   ║
    ║     ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝   ║
    ║                                                                              ║
    ║                    U L T I M A T E    E D I T I O N                          ║
    ║                         v7.0.0 - AI POWERED                                   ║
    ║                                                                              ║
    ║              🌐 Website Tracker  📱 WhatsApp Alerts  🔮 Dark Web             ║
    ║              🤖 AI Predictions  🔒 Auto Block  🔗 Blockchain                 ║
    ║                                                                              ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True, log_level="info")