#!/usr/bin/env python3

import json
import re
import sys
import time
import random
import string
import hashlib
import threading
import base64
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote
from collections import defaultdict
from typing import Dict, List, Optional, Any

import requests
import websocket
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

console = Console()

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
]

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9,es;q=0.8",
    "en-US,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.9,de;q=0.8",
    "en,en-US;q=0.9,en-GB;q=0.8",
]

ACCEPT_ENCODINGS = [
    "gzip, deflate, br",
    "gzip, deflate, br, zstd",
    "gzip, deflate",
]

API_PATTERNS = [
    (r'/api/', 'REST API'),
    (r'/v\d+/', 'Versioned API'),
    (r'/graphql', 'GraphQL'),
    (r'/rest/', 'REST'),
    (r'/ajax/', 'AJAX'),
    (r'/rpc/', 'RPC'),
    (r'/ws/', 'WebSocket'),
    (r'/socket\.io', 'Socket.IO'),
    (r'/signalr', 'SignalR'),
    (r'\.json(\?|$)', 'JSON Data'),
    (r'\.xml(\?|$)', 'XML Data'),
    (r'/feed', 'Feed'),
    (r'/data/', 'Data Endpoint'),
    (r'/query', 'Query'),
    (r'/mutation', 'Mutation'),
    (r'/subscribe', 'Subscription'),
    (r'/auth/', 'Auth Endpoint'),
    (r'/oauth/', 'OAuth'),
    (r'/token', 'Token Endpoint'),
    (r'/login', 'Login'),
    (r'/logout', 'Logout'),
    (r'/session', 'Session'),
    (r'/refresh', 'Token Refresh'),
    (r'/search', 'Search API'),
    (r'/upload', 'Upload'),
    (r'/download', 'Download'),
    (r'/webhook', 'Webhook'),
    (r'/callback', 'Callback'),
    (r'/notify', 'Notification'),
    (r'/analytics', 'Analytics'),
    (r'/tracking', 'Tracking'),
    (r'/metrics', 'Metrics'),
    (r'/health', 'Health Check'),
    (r'/status', 'Status'),
]

SENSITIVE_PATTERNS = {
    'jwt_token': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
    'api_key': r'(?i)(api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9_-]{16,})',
    'bearer_token': r'(?i)bearer\s+([a-zA-Z0-9_-]+)',
    'basic_auth': r'(?i)basic\s+([A-Za-z0-9+/=]+)',
    'aws_key': r'(?i)(AKIA[0-9A-Z]{16})',
    'private_key': r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
    'password_field': r'(?i)(password|passwd|pwd)["\s:=]+["\']?([^"\'&\s]{4,})',
    'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
    'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    'uuid': r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'session_id': r'(?i)(session[_-]?id|sid)["\s:=]+["\']?([a-zA-Z0-9_-]{16,})',
    'oauth_token': r'(?i)(access[_-]?token|refresh[_-]?token)["\s:=]+["\']?([a-zA-Z0-9_-]{16,})',
}

SENSITIVE_HEADERS = [
    'authorization',
    'x-api-key',
    'api-key',
    'x-auth-token',
    'x-access-token',
    'x-refresh-token',
    'cookie',
    'set-cookie',
    'x-csrf-token',
    'x-xsrf-token',
    'x-request-id',
    'x-correlation-id',
    'x-session-id',
    'x-user-id',
    'x-client-id',
    'x-client-secret',
    'proxy-authorization',
    'www-authenticate',
]

RATE_LIMIT_HEADERS = [
    'x-ratelimit-limit',
    'x-ratelimit-remaining',
    'x-ratelimit-reset',
    'x-rate-limit-limit',
    'x-rate-limit-remaining',
    'retry-after',
    'ratelimit-limit',
    'ratelimit-remaining',
]


class StealthConfig:
    def __init__(self):
        self.rotate_user_agent = True
        self.randomize_headers = True
        self.mask_fingerprint = True
        self.current_user_agent = random.choice(USER_AGENTS)
        self.session_id = self._generate_session_id()
        self.rotation_interval = 30
        self.last_rotation = time.time()
        
    def _generate_session_id(self) -> str:
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
    
    def get_user_agent(self) -> str:
        if self.rotate_user_agent and (time.time() - self.last_rotation) > self.rotation_interval:
            self.current_user_agent = random.choice(USER_AGENTS)
            self.last_rotation = time.time()
        return self.current_user_agent
    
    def get_random_headers(self) -> Dict[str, str]:
        return {
            'Accept-Language': random.choice(ACCEPT_LANGUAGES),
            'Accept-Encoding': random.choice(ACCEPT_ENCODINGS),
            'Cache-Control': random.choice(['no-cache', 'max-age=0']),
            'DNT': random.choice(['1', '0']),
            'Sec-Fetch-Dest': random.choice(['document', 'empty']),
            'Sec-Fetch-Mode': random.choice(['navigate', 'cors', 'no-cors']),
            'Sec-Fetch-Site': random.choice(['none', 'same-origin', 'cross-site']),
        }
    
    def anonymize_data(self, data: str) -> str:
        if len(data) > 8:
            return data[:4] + '*' * (len(data) - 8) + data[-4:]
        return '*' * len(data)


class DataAnalyzer:
    def __init__(self, stealth: StealthConfig):
        self.stealth = stealth
        
    def detect_api_type(self, url: str) -> Optional[str]:
        for pattern, api_type in API_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                return api_type
        return None
    
    def scan_for_secrets(self, text: str, anonymize: bool = True) -> List[Dict]:
        findings = []
        for secret_type, pattern in SENSITIVE_PATTERNS.items():
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                value = match.group(0)
                findings.append({
                    'type': secret_type,
                    'value': self.stealth.anonymize_data(value) if anonymize else value,
                    'position': match.start(),
                    'raw_length': len(value)
                })
        return findings
    
    def analyze_headers(self, headers: Dict) -> Dict:
        analysis = {
            'sensitive': [],
            'rate_limiting': [],
            'security': [],
            'caching': [],
            'tracking': [],
        }
        
        if not headers:
            return analysis
            
        for key, value in headers.items():
            key_lower = key.lower()
            
            if any(s in key_lower for s in SENSITIVE_HEADERS):
                analysis['sensitive'].append({
                    'header': key,
                    'value': self.stealth.anonymize_data(str(value)),
                    'raw_length': len(str(value))
                })
            
            if any(r in key_lower for r in RATE_LIMIT_HEADERS):
                analysis['rate_limiting'].append({
                    'header': key,
                    'value': value
                })
            
            if key_lower in ['strict-transport-security', 'content-security-policy', 
                           'x-frame-options', 'x-content-type-options', 'x-xss-protection']:
                analysis['security'].append({
                    'header': key,
                    'value': value[:100] if len(str(value)) > 100 else value
                })
            
            if key_lower in ['cache-control', 'expires', 'etag', 'last-modified']:
                analysis['caching'].append({
                    'header': key,
                    'value': value
                })
            
            if key_lower in ['x-request-id', 'x-correlation-id', 'x-trace-id', 'x-amzn-trace-id']:
                analysis['tracking'].append({
                    'header': key,
                    'value': self.stealth.anonymize_data(str(value))
                })
        
        return analysis
    
    def decode_jwt(self, token: str) -> Optional[Dict]:
        try:
            parts = token.split('.')
            if len(parts) >= 2:
                header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
                return {
                    'header': header,
                    'payload': payload,
                    'claims': list(payload.keys())
                }
        except:
            pass
        return None
    
    def analyze_url(self, url: str) -> Dict:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        sensitive_params = []
        tracking_params = []
        
        tracking_indicators = ['utm_', 'fbclid', 'gclid', 'ref', 'source', 'campaign', 
                             '_ga', 'mc_', 'trk', 'track']
        
        for param, values in query_params.items():
            param_lower = param.lower()
            
            if any(t in param_lower for t in tracking_indicators):
                tracking_params.append(param)
            
            for value in values:
                secrets = self.scan_for_secrets(f"{param}={value}")
                if secrets:
                    sensitive_params.extend(secrets)
        
        return {
            'scheme': parsed.scheme,
            'domain': parsed.netloc,
            'path': parsed.path,
            'query_count': len(query_params),
            'tracking_params': tracking_params,
            'sensitive_in_url': sensitive_params,
            'fragment': parsed.fragment if parsed.fragment else None
        }


class NetworkSniffer:
    def __init__(self, debug_port=9222, stealth_mode=True):
        self.debug_port = debug_port
        self.ws = None
        self.request_id = 0
        self.requests_data = {}
        self.api_endpoints = []
        self.sensitive_data = []
        self.secrets_found = []
        self.websockets_found = []
        self.rate_limits = []
        self.stats = defaultdict(int)
        self.running = False
        self.lock = threading.Lock()
        
        self.stealth = StealthConfig() if stealth_mode else None
        self.analyzer = DataAnalyzer(self.stealth if self.stealth else StealthConfig())
        
        self.domains_seen = set()
        self.api_domains = defaultdict(list)
        
    def get_ws_url(self):
        try:
            headers = {}
            if self.stealth:
                headers = {
                    'User-Agent': self.stealth.get_user_agent(),
                    **self.stealth.get_random_headers()
                }
            
            response = requests.get(
                f'http://localhost:{self.debug_port}/json',
                headers=headers,
                timeout=5
            )
            tabs = response.json()
            for tab in tabs:
                if 'webSocketDebuggerUrl' in tab:
                    return tab['webSocketDebuggerUrl'], tab.get('url', 'Unknown')
            return None, None
        except Exception as e:
            return None, None

    def analyze_request(self, data):
        request = data.get('request', {})
        url = request.get('url', '')
        method = request.get('method', 'GET')
        headers = request.get('headers', {})
        post_data = request.get('postData', '')
        
        parsed = urlparse(url)
        
        if parsed.scheme in ['chrome-extension', 'chrome', 'devtools', 'data', 'blob']:
            return None
        
        url_analysis = self.analyzer.analyze_url(url)
        header_analysis = self.analyzer.analyze_headers(headers)
        api_type = self.analyzer.detect_api_type(url)
        
        post_secrets = []
        if post_data:
            post_secrets = self.analyzer.scan_for_secrets(post_data)
        
        self.domains_seen.add(parsed.netloc)
        
        info = {
            'url': url,
            'method': method,
            'domain': parsed.netloc,
            'path': parsed.path,
            'url_analysis': url_analysis,
            'header_analysis': header_analysis,
            'post_data_length': len(post_data) if post_data else 0,
            'post_secrets': post_secrets,
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'is_api': api_type is not None,
            'api_type': api_type,
            'type': data.get('type', 'Other'),
            'initiator': data.get('initiator', {}).get('type', 'unknown'),
        }
        
        return info

    def on_message(self, ws, message):
        try:
            data = json.loads(message)
            method = data.get('method', '')
            params = data.get('params', {})
            
            with self.lock:
                if method == 'Network.requestWillBeSent':
                    request_id = params.get('requestId')
                    info = self.analyze_request(params)
                    if info:
                        self.requests_data[request_id] = info
                        self.stats['total'] += 1
                        
                        if info['is_api']:
                            self.stats['apis'] += 1
                            self.api_endpoints.append(info)
                            self.api_domains[info['domain']].append(info)
                        
                        if info['header_analysis']['sensitive']:
                            self.stats['sensitive'] += 1
                            self.sensitive_data.append(info)
                        
                        if info['post_secrets']:
                            self.stats['secrets'] += len(info['post_secrets'])
                            self.secrets_found.append(info)
                        
                        if info['url_analysis']['sensitive_in_url']:
                            self.stats['secrets'] += len(info['url_analysis']['sensitive_in_url'])
                            
                elif method == 'Network.responseReceived':
                    request_id = params.get('requestId')
                    response = params.get('response', {})
                    if request_id in self.requests_data:
                        req = self.requests_data[request_id]
                        req['status'] = response.get('status')
                        req['mime_type'] = response.get('mimeType', '')
                        
                        resp_headers = response.get('headers', {})
                        resp_analysis = self.analyzer.analyze_headers(resp_headers)
                        req['response_header_analysis'] = resp_analysis
                        
                        if resp_analysis['rate_limiting']:
                            self.rate_limits.append({
                                'domain': req['domain'],
                                'limits': resp_analysis['rate_limiting'],
                                'timestamp': datetime.now().strftime('%H:%M:%S')
                            })
                            self.stats['rate_limited'] += 1
                        
                        if resp_analysis['sensitive']:
                            if req not in self.sensitive_data:
                                self.sensitive_data.append(req)
                                self.stats['sensitive'] += 1
                                
                elif method == 'Network.webSocketCreated':
                    ws_url = params.get('url', '')
                    self.websockets_found.append({
                        'url': ws_url,
                        'timestamp': datetime.now().strftime('%H:%M:%S'),
                        'analysis': self.analyzer.analyze_url(ws_url)
                    })
                    self.stats['websockets'] += 1
                    
                elif method == 'Network.webSocketFrameReceived':
                    payload = params.get('response', {}).get('payloadData', '')
                    if payload:
                        secrets = self.analyzer.scan_for_secrets(payload)
                        if secrets:
                            self.stats['secrets'] += len(secrets)
                    
        except Exception as e:
            pass

    def on_error(self, ws, error):
        console.print(f"[red]WebSocket Error: {error}[/red]")

    def on_close(self, ws, close_status_code, close_msg):
        console.print("[yellow]Connection closed[/yellow]")
        self.running = False

    def on_open(self, ws):
        ws.send(json.dumps({'id': 1, 'method': 'Network.enable', 'params': {
            'maxTotalBufferSize': 10000000,
            'maxResourceBufferSize': 5000000
        }}))
        ws.send(json.dumps({'id': 2, 'method': 'Network.setCacheDisabled', 'params': {'cacheDisabled': False}}))
        console.print("[green]✓ Advanced network monitoring enabled[/green]")
        self.running = True

    def create_display(self):
        stats_text = Text()
        stats_text.append(f"📊 Requests: {self.stats['total']}  ", style="cyan")
        stats_text.append(f"🔌 APIs: {self.stats['apis']}  ", style="green")
        stats_text.append(f"🔐 Sensitive: {self.stats['sensitive']}  ", style="yellow")
        stats_text.append(f"🔑 Secrets: {self.stats['secrets']}  ", style="red")
        stats_text.append(f"🌐 WS: {self.stats['websockets']}  ", style="magenta")
        stats_text.append(f"⚠️ Rate Limits: {self.stats['rate_limited']}", style="bright_red")
        
        stealth_text = Text()
        if self.stealth:
            stealth_text.append("🛡️ STEALTH MODE: ", style="bold green")
            stealth_text.append(f"UA Rotation ✓  ", style="green")
            stealth_text.append(f"Session: {self.stealth.session_id[:8]}...  ", style="dim")
            stealth_text.append(f"Domains: {len(self.domains_seen)}", style="cyan")
        
        api_table = Table(title="🔌 API Endpoints Detected", box=box.ROUNDED, expand=True)
        api_table.add_column("Time", style="dim", width=8)
        api_table.add_column("Type", style="magenta", width=12)
        api_table.add_column("Method", style="cyan", width=6)
        api_table.add_column("Domain", style="yellow", width=25)
        api_table.add_column("Path", style="green", overflow="fold")
        api_table.add_column("Status", width=6)
        
        with self.lock:
            for api in self.api_endpoints[-8:]:
                status = api.get('status', '-')
                status_style = "green" if status == 200 else "yellow" if status in [201, 204] else "red" if status and status >= 400 else "dim"
                path = api['path']
                if len(path) > 40:
                    path = path[:37] + '...'
                api_table.add_row(
                    api['timestamp'],
                    api['api_type'] or '-',
                    api['method'],
                    api['domain'][:25],
                    path,
                    Text(str(status), style=status_style)
                )
        
        secrets_table = Table(title="🔑 Secrets & Sensitive Data Found", box=box.ROUNDED, expand=True)
        secrets_table.add_column("Time", style="dim", width=8)
        secrets_table.add_column("Domain", style="cyan", width=20)
        secrets_table.add_column("Type", style="yellow", width=15)
        secrets_table.add_column("Location", style="magenta", width=12)
        secrets_table.add_column("Value (masked)", style="red", overflow="fold")
        
        with self.lock:
            displayed = 0
            for req in self.sensitive_data[-6:]:
                for header_info in req.get('header_analysis', {}).get('sensitive', [])[:2]:
                    if displayed < 8:
                        secrets_table.add_row(
                            req['timestamp'],
                            req['domain'][:20],
                            header_info['header'][:15],
                            'Header',
                            header_info['value'][:40]
                        )
                        displayed += 1
            
            for req in self.secrets_found[-4:]:
                for secret in req.get('post_secrets', [])[:2]:
                    if displayed < 8:
                        secrets_table.add_row(
                            req['timestamp'],
                            req['domain'][:20],
                            secret['type'][:15],
                            'POST Body',
                            secret['value'][:40]
                        )
                        displayed += 1
        
        rate_table = Table(title="⚠️ Rate Limiting Detected", box=box.ROUNDED, expand=True)
        rate_table.add_column("Time", style="dim", width=8)
        rate_table.add_column("Domain", style="cyan", width=25)
        rate_table.add_column("Limit", style="yellow", width=15)
        rate_table.add_column("Remaining", style="green", width=15)
        
        with self.lock:
            for rl in self.rate_limits[-4:]:
                limit_val = '-'
                remaining_val = '-'
                for l in rl['limits']:
                    if 'limit' in l['header'].lower() and 'remaining' not in l['header'].lower():
                        limit_val = str(l['value'])
                    if 'remaining' in l['header'].lower():
                        remaining_val = str(l['value'])
                rate_table.add_row(
                    rl['timestamp'],
                    rl['domain'][:25],
                    limit_val,
                    remaining_val
                )
        
        ws_table = Table(title="🌐 WebSocket Connections", box=box.ROUNDED, expand=True)
        ws_table.add_column("Time", style="dim", width=8)
        ws_table.add_column("Domain", style="cyan", width=25)
        ws_table.add_column("URL", style="magenta", overflow="fold")
        
        with self.lock:
            for ws_conn in self.websockets_found[-4:]:
                ws_table.add_row(
                    ws_conn['timestamp'],
                    ws_conn['analysis']['domain'][:25],
                    ws_conn['url'][:60] + ('...' if len(ws_conn['url']) > 60 else '')
                )
        
        content = f"{stats_text}\n{stealth_text}\n\n"
        content += str(api_table) + "\n\n"
        content += str(secrets_table) + "\n\n"
        
        if self.rate_limits:
            content += str(rate_table) + "\n\n"
        
        if self.websockets_found:
            content += str(ws_table)
        
        return Panel(
            content,
            title="[bold cyan]🔍 Advanced Network Sniffer - Press Ctrl+C to stop[/bold cyan]",
            border_style="cyan"
        )

    def connect(self):
        ws_url, page_url = self.get_ws_url()
        
        if not ws_url:
            console.print(Panel(
                "[bold red]Could not connect to Chrome![/bold red]\n\n"
                "Please start Chrome with remote debugging enabled:\n\n"
                "[cyan]chrome.exe --remote-debugging-port=9222[/cyan]\n\n"
                "Or for a new profile:\n"
                "[cyan]chrome.exe --remote-debugging-port=9222 --user-data-dir=C:\\\\temp\\\\chrome-debug[/cyan]",
                title="Connection Error",
                border_style="red"
            ))
            return False
        
        console.print(f"[green]✓ Found browser tab: {page_url[:60]}...[/green]" if len(page_url) > 60 else f"[green]✓ Found browser tab: {page_url}[/green]")
        
        if self.stealth:
            console.print(f"[green]✓ Stealth mode active - Session: {self.stealth.session_id}[/green]")
            console.print(f"[dim]  User-Agent: {self.stealth.get_user_agent()[:60]}...[/dim]")
        
        self.ws = websocket.WebSocketApp(
            ws_url,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close,
            on_open=self.on_open
        )
        
        return True

    def run(self):
        if not self.connect():
            return
        
        ws_thread = threading.Thread(target=self.ws.run_forever)
        ws_thread.daemon = True
        ws_thread.start()
        
        time.sleep(1)
        
        if not self.running:
            console.print("[red]Failed to establish connection[/red]")
            return
        
        console.print("\n[bold green]🚀 Advanced Sniffer is running! Browse any website to capture traffic.[/bold green]\n")
        
        try:
            with Live(self.create_display(), refresh_per_second=2, console=console) as live:
                while self.running:
                    if self.stealth:
                        self.stealth.get_user_agent()
                    live.update(self.create_display())
                    time.sleep(0.5)
        except KeyboardInterrupt:
            console.print("\n[yellow]Stopping sniffer...[/yellow]")
            self.export_results()

    def export_results(self):
        if not self.api_endpoints and not self.sensitive_data:
            console.print("[dim]No data captured to export[/dim]")
            return
            
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        suffix = ''.join(random.choices(string.ascii_lowercase, k=4))
        filename = f'sniffer_{suffix}_{timestamp}.json'
        
        export_data = {
            'captured_at': datetime.now().isoformat(),
            'session_id': self.stealth.session_id if self.stealth else 'no-stealth',
            'stats': dict(self.stats),
            'domains_analyzed': list(self.domains_seen),
            'api_endpoints': [
                {
                    'url': api['url'],
                    'method': api['method'],
                    'domain': api['domain'],
                    'api_type': api['api_type'],
                    'status': api.get('status'),
                    'timestamp': api['timestamp'],
                    'initiator': api.get('initiator')
                }
                for api in self.api_endpoints
            ],
            'sensitive_findings': [
                {
                    'domain': req['domain'],
                    'path': req['path'],
                    'sensitive_headers': req.get('header_analysis', {}).get('sensitive', []),
                    'timestamp': req['timestamp']
                }
                for req in self.sensitive_data
            ],
            'secrets_detected': [
                {
                    'domain': req['domain'],
                    'secrets': req.get('post_secrets', [])
                }
                for req in self.secrets_found
            ],
            'websockets': [
                {
                    'url': ws['url'],
                    'domain': ws['analysis']['domain'],
                    'timestamp': ws['timestamp']
                }
                for ws in self.websockets_found
            ],
            'rate_limits': self.rate_limits,
            'api_by_domain': {
                domain: [{'path': api['path'], 'method': api['method'], 'type': api['api_type']} 
                        for api in apis]
                for domain, apis in self.api_domains.items()
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        console.print(f"\n[green]✓ Results exported to: {filename}[/green]")
        console.print(f"[dim]  Total APIs: {len(self.api_endpoints)} | Domains: {len(self.domains_seen)} | Secrets: {self.stats['secrets']}[/dim]")


def main():
    console.print(Panel.fit(
        "[bold cyan]🔍 Advanced Network Sniffer[/bold cyan]\n"
        "[dim]Captures APIs, secrets, and network traffic with stealth features[/dim]\n\n"
        "[green]✓[/green] User-Agent Rotation\n"
        "[green]✓[/green] Data Anonymization\n"
        "[green]✓[/green] Secret Detection (JWT, API Keys, Tokens)\n"
        "[green]✓[/green] Rate Limit Monitoring",
        border_style="cyan"
    ))
    
    port = 9222
    stealth = True
    
    for arg in sys.argv[1:]:
        if arg == '--no-stealth':
            stealth = False
        elif arg.isdigit():
            port = int(arg)
    
    if stealth:
        console.print("\n[bold green]🛡️ Stealth Mode Enabled[/bold green]")
        console.print("[dim]- User agents will rotate every 30 seconds[/dim]")
        console.print("[dim]- Sensitive data will be automatically masked[/dim]")
        console.print("[dim]- Export files use randomized names[/dim]\n")
    else:
        console.print("\n[yellow]⚠️ Stealth Mode Disabled[/yellow]\n")
    
    sniffer = NetworkSniffer(debug_port=port, stealth_mode=stealth)
    sniffer.run()


if __name__ == '__main__':
    main()
