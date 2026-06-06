// ============================================
// NETWATCH - ADVANCED JAVASCRIPT
// WebSocket | Real-time | Charts | Alerts
// ============================================

// Configuration
const WS_URL = `ws://${window.location.hostname}:8000/ws`;
const API_BASE = `http://${window.location.hostname}:8000`;

// Global Variables
let ws = null;
let charts = {};
let alertSound = null;
let reconnectAttempts = 0;
let darkMode = localStorage.getItem('darkMode') === 'enabled';

// Initialize Audio for Alerts
function initAudio() {
    alertSound = new Audio('data:audio/wav;base64,U3RlYWx0aCBzb3VuZCBub3QgbG9hZGVk');
    alertSound.volume = 0.5;
}

// Play Alert Sound
function playAlertSound() {
    if (alertSound) {
        alertSound.play().catch(e => console.log('Audio not supported'));
    }
}

// Show Desktop Notification
function showNotification(title, body, severity = 'info') {
    if (Notification.permission === 'granted') {
        new Notification(title, { body, icon: '/favicon.ico' });
        playAlertSound();
    } else if (Notification.permission !== 'denied') {
        Notification.requestPermission();
    }
}

// WebSocket Connection
function connectWebSocket() {
    console.log('Connecting to WebSocket...');
    
    ws = new WebSocket(WS_URL);
    
    ws.onopen = () => {
        console.log('WebSocket connected');
        document.getElementById('ws-status')?.classList.add('connected');
        reconnectAttempts = 0;
        updateWSIndicator(true);
    };
    
    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        handleWebSocketData(data);
    };
    
    ws.onclose = () => {
        console.log('WebSocket disconnected');
        updateWSIndicator(false);
        setTimeout(reconnectWebSocket, 3000);
    };
    
    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
    };
}

function reconnectWebSocket() {
    reconnectAttempts++;
    const delay = Math.min(3000 * reconnectAttempts, 30000);
    console.log(`Reconnecting in ${delay}ms...`);
    setTimeout(connectWebSocket, delay);
}

function updateWSIndicator(connected) {
    const indicator = document.getElementById('ws-indicator');
    if (indicator) {
        indicator.innerHTML = connected ? '🟢 Live' : '🔴 Disconnected';
        indicator.style.color = connected ? '#00e676' : '#ff3b30';
    }
}

// Handle WebSocket Data
function handleWebSocketData(data) {
    if (data.type === 'metrics') {
        updateDashboard(data);
        updateCharts(data);
        updateAdaptersTable(data.adapters);
        updateProcessesTable(data.top_processes);
        updateConnectionsTable(data.live_connections);
        updateAlertsList(data.alerts);
    } else if (data.type === 'alert') {
        addAlertToList(data.data);
        showNotification(data.data.title, data.data.message, data.data.severity);
    }
}

// Update Dashboard Numbers
function updateDashboard(data) {
    const elements = {
        'total-download': data.total_mbps_recv?.toFixed(2) || '0',
        'total-upload': data.total_mbps_sent?.toFixed(2) || '0',
        'total-bandwidth': data.total_mbps?.toFixed(2) || '0',
        'cpu-usage': data.system?.cpu_pct?.toFixed(1) || '0',
        'memory-usage': `${data.system?.mem_used_gb || 0} / ${data.system?.mem_total_gb || 0} GB`,
        'memory-percent': data.system?.mem_pct?.toFixed(1) || '0',
        'active-connections': data.active_connections || '0',
        'ws-clients': data.ws_clients || '0',
        'packet-rate': data.packet_rate_pps?.toFixed(0) || '0'
    };
    
    for (const [id, value] of Object.entries(elements)) {
        const el = document.getElementById(id);
        if (el) el.textContent = value;
    }
    
    // Update CPU/Memory progress bars
    const cpuBar = document.getElementById('cpu-bar');
    if (cpuBar) cpuBar.style.width = `${data.system?.cpu_pct || 0}%`;
    
    const memBar = document.getElementById('mem-bar');
    if (memBar) memBar.style.width = `${data.system?.mem_pct || 0}%`;
    
    // Update prediction
    const predictionEl = document.getElementById('prediction-value');
    if (predictionEl && data.prediction) {
        predictionEl.textContent = `${data.prediction.next_mbps} Mbps`;
    }
}

// Initialize Charts
function initCharts() {
    const ctx = document.getElementById('traffic-chart')?.getContext('2d');
    if (!ctx) return;
    
    charts.traffic = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Download (Mbps)',
                    data: [],
                    borderColor: '#00d4ff',
                    backgroundColor: 'rgba(0, 212, 255, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                },
                {
                    label: 'Upload (Mbps)',
                    data: [],
                    borderColor: '#6c63ff',
                    backgroundColor: 'rgba(108, 99, 255, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { labels: { color: '#ffffff' } },
                tooltip: { mode: 'index', intersect: false }
            },
            scales: {
                x: { grid: { color: 'rgba(255,255,255,0.1)' }, ticks: { color: '#a0a8c0' } },
                y: { grid: { color: 'rgba(255,255,255,0.1)' }, ticks: { color: '#a0a8c0' }, title: { display: true, text: 'Mbps', color: '#ffffff' } }
            },
            interaction: { mode: 'nearest', axis: 'x', intersect: false }
        }
    });
}

function updateCharts(data) {
    if (!charts.traffic) return;
    
    const history = data.traffic_history || [];
    const labels = history.map(p => p.time_str);
    const downloadData = history.map(p => p.mbps_recv);
    const uploadData = history.map(p => p.mbps_sent);
    
    charts.traffic.data.labels = labels;
    charts.traffic.data.datasets[0].data = downloadData;
    charts.traffic.data.datasets[1].data = uploadData;
    charts.traffic.update('none');
}

// Update Adapters Table
function updateAdaptersTable(adapters) {
    const tbody = document.getElementById('adapters-table-body');
    if (!tbody) return;
    
    tbody.innerHTML = adapters.map(adapter => `
        <tr>
            <td><strong>${adapter.name}</strong></td>
            <td>${adapter.ipv4 || '-'}</td>
            <td><span class="status-badge ${adapter.is_up ? 'up' : 'down'}">${adapter.is_up ? '🟢 UP' : '🔴 DOWN'}</span></td>
            <td>${adapter.speed_mbps || '-'} Mbps</td>
            <td class="download-value">${adapter.mbps_recv.toFixed(2)}</td>
            <td class="upload-value">${adapter.mbps_sent.toFixed(2)}</td>
            <td>${adapter.errors_in || 0}</td>
        </tr>
    `).join('');
}

// Update Processes Table
function updateProcessesTable(processes) {
    const tbody = document.getElementById('processes-table-body');
    if (!tbody) return;
    
    tbody.innerHTML = processes.map((proc, i) => `
        <tr>
            <td>${i + 1}</td>
            <td>${proc.name}</td>
            <td><div class="progress-bar" style="width: ${Math.min(proc.mbps * 2, 100)}%"></div>${proc.mbps.toFixed(2)} Mbps</td>
        </tr>
    `).join('');
}

// Update Connections Table
function updateConnectionsTable(connections) {
    const tbody = document.getElementById('connections-table-body');
    if (!tbody) return;
    
    tbody.innerHTML = connections.map(conn => `
        <tr>
            <td>${conn.local_ip}:${conn.local_port}</td>
            <td>→ ${conn.remote_ip}:${conn.remote_port}</td>
            <td>${conn.process || 'system'}</td>
            <td><span class="status-badge">${conn.status || 'ESTABLISHED'}</span></td>
        </tr>
    `).join('');
}

// Update Alerts List
function updateAlertsList(alerts) {
    const container = document.getElementById('alerts-container');
    if (!container) return;
    
    if (!alerts || alerts.length === 0) {
        container.innerHTML = '<div class="no-alerts">✅ No active alerts</div>';
        return;
    }
    
    container.innerHTML = alerts.map(alert => `
        <div class="alert-item ${alert.severity || alert.alert_type}">
            <div class="alert-title">${alert.title || alert.alert_type}</div>
            <div class="alert-message">${alert.message}</div>
            <div class="alert-time">${new Date(alert.timestamp * 1000).toLocaleTimeString()}</div>
            <button onclick="acknowledgeAlert(${alert.id})" class="btn-ack">Acknowledge</button>
        </div>
    `).join('');
}

function addAlertToList(alert) {
    const container = document.getElementById('alerts-container');
    if (!container) return;
    
    const alertHtml = `
        <div class="alert-item ${alert.severity}">
            <div class="alert-title">${alert.title}</div>
            <div class="alert-message">${alert.message}</div>
            <div class="alert-time">${new Date(alert.timestamp * 1000).toLocaleTimeString()}</div>
        </div>
    `;
    container.insertAdjacentHTML('afterbegin', alertHtml);
}

function acknowledgeAlert(alertId) {
    fetch(`${API_BASE}/api/alerts/${alertId}/acknowledge`, { method: 'POST' })
        .then(() => console.log('Alert acknowledged'))
        .catch(err => console.error('Error:', err));
}

// Fetch Initial Data
async function fetchInitialData() {
    try {
        const response = await fetch(`${API_BASE}/api/dashboard`);
        const data = await response.json();
        updateDashboard(data.metrics);
        updateCharts(data.metrics);
        updateAdaptersTable(data.metrics.adapters);
        updateProcessesTable(data.metrics.top_processes);
        updateConnectionsTable(data.metrics.live_connections);
    } catch (error) {
        console.error('Fetch error:', error);
    }
}

// Refresh Data (Fallback)
function refreshData() {
    fetchInitialData();
}

// Export Data
function exportData(format) {
    window.open(`${API_BASE}/api/export/${format}?hours=24`, '_blank');
}

// Theme Toggle
function toggleTheme() {
    darkMode = !darkMode;
    localStorage.setItem('darkMode', darkMode ? 'enabled' : 'disabled');
    document.body.classList.toggle('light-mode', !darkMode);
}

// Page Navigation
function navigateTo(page) {
    window.location.href = page;
}

// Initialize on Page Load
document.addEventListener('DOMContentLoaded', () => {
    console.log('NetWatch Frontend Initialized');
    
    initAudio();
    initCharts();
    connectWebSocket();
    fetchInitialData();
    
    // Refresh every 30 seconds as fallback
    setInterval(refreshData, 30000);
    
    // Update time every second
    setInterval(() => {
        const timeEl = document.getElementById('live-time');
        if (timeEl) {
            timeEl.textContent = new Date().toLocaleTimeString();
        }
    }, 1000);
});